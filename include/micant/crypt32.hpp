#pragma once

/**
 * @file crypt32.hpp
 * @brief MicaNT Clean-Room Windows Cryptography API & Certificate Store (crypt32.dll).
 *
 * Implements DPAPI (CryptProtectData / CryptUnprotectData), Base64 / Hex formatters
 * (CryptBinaryToString / CryptStringToBinary), Certificate Contexts, and X.509
 * Certificate Stores (CertOpenSystemStore, CertFindCertificateInStore, CertEnumCertificatesInStore).
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstring>
#include <span>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "kernel32.hpp"
#include "cipherksp.hpp"
#include "ldr.hpp"

namespace micant::crypt32 {

// ============================================================================
// 1. Standard Crypt32 Constants & Type Definitions
// ============================================================================

struct DATA_BLOB {
    uint32_t cbData{0};
    uint8_t* pbData{nullptr};
};

struct CRYPT_ALGORITHM_IDENTIFIER {
    const char* pszObjId{nullptr};
    DATA_BLOB   Parameters{};
};

struct CERT_PUBLIC_KEY_INFO {
    CRYPT_ALGORITHM_IDENTIFIER Algorithm{};
    struct {
        uint32_t cbData{0};
        uint8_t* pbData{nullptr};
        uint32_t cUnusedBits{0};
    } PublicKey{};
};

struct CERT_INFO {
    uint32_t dwVersion{2}; // v3 (0-indexed: 2)
    DATA_BLOB SerialNumber{};
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm{};
    DATA_BLOB Issuer{};
    win32::FILETIME NotBefore{};
    win32::FILETIME NotAfter{};
    DATA_BLOB Subject{};
    CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo{};
};

using HCERTSTORE = void*;

struct CERT_CONTEXT {
    uint32_t dwCertEncodingType{0x00000001}; // X509_ASN_ENCODING
    uint8_t* pbCertEncoded{nullptr};
    uint32_t cbCertEncoded{0};
    CERT_INFO* pCertInfo{nullptr};
    HCERTSTORE hCertStore{nullptr};
};

using PCERT_CONTEXT  = const CERT_CONTEXT*;
using PCCERT_CONTEXT = const CERT_CONTEXT*;

struct CRYPTPROTECT_PROMPTSTRUCT {
    uint32_t cbSize{0};
    uint32_t dwPromptFlags{0};
    win32::HWND hwndApp{nullptr};
    const wchar_t* szPrompt{nullptr};
};

// DPAPI Flags
inline constexpr uint32_t CRYPTPROTECT_UI_FORBIDDEN     = 0x00000001;
inline constexpr uint32_t CRYPTPROTECT_LOCAL_MACHINE    = 0x00000004;
inline constexpr uint32_t CRYPTPROTECT_AUDIT            = 0x00000010;
inline constexpr uint32_t CRYPTPROTECT_VERIFY_PROTECTION= 0x00000040;

// Formatting Flags (CryptBinaryToString / CryptStringToBinary)
inline constexpr uint32_t CRYPT_STRING_BASE64HEADER        = 0x00000000;
inline constexpr uint32_t CRY_STRING_BASE64               = 0x00000001;
inline constexpr uint32_t CRYPT_STRING_BASE64             = 0x00000001;
inline constexpr uint32_t CRYPT_STRING_BINARY             = 0x00000002;
inline constexpr uint32_t CRYPT_STRING_BASE64REQUESTHEADER= 0x00000003;
inline constexpr uint32_t CRYPT_STRING_HEX                = 0x00000004;
inline constexpr uint32_t CRYPT_STRING_HEXASCII           = 0x00000005;
inline constexpr uint32_t CRYPT_STRING_BASE64_ANY         = 0x00000006;
inline constexpr uint32_t CRYPT_STRING_HEX_ANY            = 0x00000008;
inline constexpr uint32_t CRYPT_STRING_HEXADDR            = 0x0000000a;
inline constexpr uint32_t CRYPT_STRING_HEXASCIIADDR       = 0x0000000b;
inline constexpr uint32_t CRYPT_STRING_HEXRAW             = 0x0000000c;
inline constexpr uint32_t CRYPT_STRING_NOCRLF             = 0x40000000;
inline constexpr uint32_t CRYPT_STRING_NOCR               = 0x80000000;

// Certificate Store Providers & Flags
inline constexpr uintptr_t CERT_STORE_PROV_MEMORY         = 2;
inline constexpr uintptr_t CERT_STORE_PROV_SYSTEM         = 10;
inline constexpr uintptr_t CERT_STORE_PROV_SYSTEM_W       = 10;

inline constexpr uint32_t CERT_STORE_NO_CRYPT_RELEASE_FLAG= 0x00000001;
inline constexpr uint32_t CERT_STORE_READONLY_FLAG        = 0x00008000;
inline constexpr uint32_t CERT_STORE_OPEN_EXISTING_FLAG   = 0x00004000;
inline constexpr uint32_t CERT_STORE_CREATE_NEW_FLAG      = 0x00002000;

inline constexpr uint32_t CERT_SYSTEM_STORE_CURRENT_USER  = 0x00010000;
inline constexpr uint32_t CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000;

// Add Dispositions
inline constexpr uint32_t CERT_STORE_ADD_NEW              = 1;
inline constexpr uint32_t CERT_STORE_ADD_USE_EXISTING     = 2;
inline constexpr uint32_t CERT_STORE_ADD_REPLACE_EXISTING = 3;
inline constexpr uint32_t CERT_STORE_ADD_ALWAYS           = 4;

// Find Types
inline constexpr uint32_t CERT_FIND_ANY                   = 0;
inline constexpr uint32_t CERT_FIND_SHA1_HASH             = 0x00010000;
inline constexpr uint32_t CERT_FIND_MD5_HASH              = 0x00040000;
inline constexpr uint32_t CERT_FIND_PROPERTY              = 0x00050000;
inline constexpr uint32_t CERT_FIND_SUBJECT_STR_A         = 0x00070007;
inline constexpr uint32_t CERT_FIND_SUBJECT_STR_W         = 0x00080007;
inline constexpr uint32_t CERT_FIND_ISSUER_STR_A          = 0x00070004;
inline constexpr uint32_t CERT_FIND_ISSUER_STR_W          = 0x00080004;

// Name Types
inline constexpr uint32_t CERT_NAME_EMAIL_TYPE            = 1;
inline constexpr uint32_t CERT_NAME_RDN_TYPE              = 2;
inline constexpr uint32_t CERT_NAME_SIMPLE_DISPLAY_TYPE   = 4;
inline constexpr uint32_t CERT_NAME_FRIENDLY_DISPLAY_TYPE = 5;
inline constexpr uint32_t CERT_NAME_DNS_TYPE              = 6;
inline constexpr uint32_t CERT_NAME_URL_TYPE              = 7;

// Name Flags
inline constexpr uint32_t CERT_NAME_ISSUER_FLAG           = 0x00000001;
inline constexpr uint32_t CERT_NAME_DISABLE_IE4_UTF8_FLAG = 0x00010000;

// Certificate Property IDs
inline constexpr uint32_t CERT_KEY_PROV_HANDLE_PROP_ID    = 1;
inline constexpr uint32_t CERT_KEY_PROV_INFO_PROP_ID      = 2;
inline constexpr uint32_t CERT_SHA1_HASH_PROP_ID          = 3;
inline constexpr uint32_t CERT_MD5_HASH_PROP_ID           = 4;
inline constexpr uint32_t CERT_KEY_CONTEXT_PROP_ID        = 5;
inline constexpr uint32_t CERT_FRIENDLY_NAME_PROP_ID      = 11;

inline constexpr uint32_t X509_ASN_ENCODING               = 0x00000001;
inline constexpr uint32_t PKCS_7_ASN_ENCODING             = 0x00010000;

// Win32 Error codes for crypto
inline constexpr uint32_t CRYPT_E_NOT_FOUND               = 0x80092004;
inline constexpr uint32_t CRYPT_E_EXISTS                  = 0x80092005;
inline constexpr uint32_t NTE_BAD_DATA                    = 0x80090005;
inline constexpr uint32_t ERROR_INVALID_PARAMETER         = 87;
inline constexpr uint32_t ERROR_INSUFFICIENT_BUFFER       = 122;

// ============================================================================
// 2. Data Protection API (DPAPI) Implementation
// ============================================================================

namespace detail {
    inline const uint8_t DPAPI_MAGIC[8] = { 'M', 'I', 'C', 'A', 'D', 'P', 0x01, 0x00 };
    inline const uint8_t DPAPI_MASTER_SEED[32] = {
        0x53, 0x6f, 0x76, 0x65, 0x72, 0x65, 0x69, 0x67, // "Sovereig"
        0x6e, 0x4d, 0x69, 0x63, 0x61, 0x4e, 0x54, 0x43, // "nMicaNTC"
        0x6f, 0x72, 0x65, 0x44, 0x50, 0x41, 0x50, 0x49, // "oreDPAPI"
        0x32, 0x30, 0x32, 0x36, 0x46, 0x49, 0x50, 0x53  // "2026FIPS"
    };
}

inline win32::BOOL CryptProtectData(
    DATA_BLOB* pDataIn,
    const wchar_t* szDataDescr,
    DATA_BLOB* pOptionalEntropy,
    [[maybe_unused]] void* pvReserved,
    [[maybe_unused]] CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
    [[maybe_unused]] uint32_t dwFlags,
    DATA_BLOB* pDataOut
) {
    if (!pDataIn || !pDataIn->pbData || pDataIn->cbData == 0 || !pDataOut) {
        win32::SetLastError(ERROR_INVALID_PARAMETER);
        return win32::FALSE;
    }

    // 1. Generate 16 bytes random salt and 16 bytes random IV
    uint8_t salt[16]{};
    uint8_t iv[16]{};
    crypto::Csprng::get().getBytes(salt);
    crypto::Csprng::get().getBytes(iv);

    // 2. Derive key material using PBKDF2
    std::vector<uint8_t> password(std::begin(detail::DPAPI_MASTER_SEED), std::end(detail::DPAPI_MASTER_SEED));
    if (pOptionalEntropy && pOptionalEntropy->pbData && pOptionalEntropy->cbData > 0) {
        password.insert(password.end(), pOptionalEntropy->pbData, pOptionalEntropy->pbData + pOptionalEntropy->cbData);
    }

    auto derived = crypto::Pbkdf2::derive(password, salt, 2048, 64);
    std::span<const uint8_t> encKey(derived.data(), 32);
    std::span<const uint8_t> hmacKey(derived.data() + 32, 32);

    // 3. Encrypt payload using AES-256-CBC
    crypto::Aes aes(encKey);
    auto ciphertext = aes.encrypt(
        std::span<const uint8_t>(pDataIn->pbData, pDataIn->cbData),
        crypto::Aes::Mode::CBC,
        iv,
        true
    );

    // 4. Construct output blob and compute HMAC authentication tag
    // Layout:
    // [Header: 8] [Salt: 16] [IV: 16] [DescBytes: 4] [Desc: DescBytes] [CtLen: 4] [Ciphertext: CtLen] [HMAC: 32]
    uint32_t descBytes = 0;
    if (szDataDescr) {
        descBytes = static_cast<uint32_t>((std::wcslen(szDataDescr) + 1) * sizeof(wchar_t));
    }
    uint32_t ctLen = static_cast<uint32_t>(ciphertext.size());
    uint32_t totalBytes = 8 + 16 + 16 + 4 + descBytes + 4 + ctLen + 32;

    auto* outBuf = static_cast<uint8_t*>(win32::LocalAlloc(0x0040 /*LPTR*/, totalBytes));
    if (!outBuf) {
        win32::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return win32::FALSE;
    }

    size_t off = 0;
    std::memcpy(outBuf + off, detail::DPAPI_MAGIC, 8); off += 8;
    std::memcpy(outBuf + off, salt, 16); off += 16;
    std::memcpy(outBuf + off, iv, 16); off += 16;
    std::memcpy(outBuf + off, &descBytes, 4); off += 4;
    if (descBytes > 0) {
        std::memcpy(outBuf + off, szDataDescr, descBytes); off += descBytes;
    }
    std::memcpy(outBuf + off, &ctLen, 4); off += 4;
    std::memcpy(outBuf + off, ciphertext.data(), ctLen); off += ctLen;

    // HMAC-SHA256 authenticates entire header, metadata, and ciphertext
    crypto::HmacSha256::Context hmacCtx;
    crypto::HmacSha256::init(hmacCtx, hmacKey);
    crypto::HmacSha256::update(hmacCtx, std::span<const uint8_t>(outBuf, off));
    uint8_t hmacTag[32]{};
    crypto::HmacSha256::final(hmacCtx, hmacTag);

    std::memcpy(outBuf + off, hmacTag, 32);

    pDataOut->cbData = totalBytes;
    pDataOut->pbData = outBuf;
    return win32::TRUE;
}

inline win32::BOOL CryptUnprotectData(
    DATA_BLOB* pDataIn,
    wchar_t** ppszDataDescr,
    DATA_BLOB* pOptionalEntropy,
    [[maybe_unused]] void* pvReserved,
    [[maybe_unused]] CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
    [[maybe_unused]] uint32_t dwFlags,
    DATA_BLOB* pDataOut
) {
    if (!pDataIn || !pDataIn->pbData || pDataIn->cbData < (8 + 16 + 16 + 4 + 4 + 16 + 32) || !pDataOut) {
        win32::SetLastError(ERROR_INVALID_PARAMETER);
        return win32::FALSE;
    }

    const uint8_t* in = pDataIn->pbData;
    if (std::memcmp(in, detail::DPAPI_MAGIC, 8) != 0) {
        win32::SetLastError(NTE_BAD_DATA);
        return win32::FALSE;
    }

    size_t off = 8;
    const uint8_t* salt = in + off; off += 16;
    const uint8_t* iv   = in + off; off += 16;

    uint32_t descBytes = 0;
    std::memcpy(&descBytes, in + off, 4); off += 4;
    if (off + descBytes + 4 + 32 > pDataIn->cbData) {
        win32::SetLastError(NTE_BAD_DATA);
        return win32::FALSE;
    }

    const wchar_t* pDescInBlob = nullptr;
    if (descBytes > 0) {
        pDescInBlob = reinterpret_cast<const wchar_t*>(in + off);
        off += descBytes;
    }

    uint32_t ctLen = 0;
    std::memcpy(&ctLen, in + off, 4); off += 4;
    if (off + ctLen + 32 != pDataIn->cbData) {
        win32::SetLastError(NTE_BAD_DATA);
        return win32::FALSE;
    }

    const uint8_t* ciphertext = in + off; off += ctLen;
    const uint8_t* expectedTag = in + off;

    // Derive key material using PBKDF2
    std::vector<uint8_t> password(std::begin(detail::DPAPI_MASTER_SEED), std::end(detail::DPAPI_MASTER_SEED));
    if (pOptionalEntropy && pOptionalEntropy->pbData && pOptionalEntropy->cbData > 0) {
        password.insert(password.end(), pOptionalEntropy->pbData, pOptionalEntropy->pbData + pOptionalEntropy->cbData);
    }

    auto derived = crypto::Pbkdf2::derive(password, std::span<const uint8_t>(salt, 16), 2048, 64);
    std::span<const uint8_t> encKey(derived.data(), 32);
    std::span<const uint8_t> hmacKey(derived.data() + 32, 32);

    // Verify HMAC-SHA256
    crypto::HmacSha256::Context hmacCtx;
    crypto::HmacSha256::init(hmacCtx, hmacKey);
    crypto::HmacSha256::update(hmacCtx, std::span<const uint8_t>(in, pDataIn->cbData - 32));
    uint8_t computedTag[32]{};
    crypto::HmacSha256::final(hmacCtx, computedTag);

    // Constant-time check
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; ++i) {
        diff |= (computedTag[i] ^ expectedTag[i]);
    }
    if (diff != 0) {
        win32::SetLastError(NTE_BAD_DATA);
        return win32::FALSE;
    }

    // Decrypt ciphertext using AES-256-CBC
    crypto::Aes aes(encKey);
    bool ok = false;
    auto plaintext = aes.decrypt(
        std::span<const uint8_t>(ciphertext, ctLen),
        crypto::Aes::Mode::CBC,
        std::span<const uint8_t>(iv, 16),
        true,
        &ok
    );

    if (!ok) {
        win32::SetLastError(NTE_BAD_DATA);
        return win32::FALSE;
    }

    // Return description if requested
    if (ppszDataDescr) {
        if (pDescInBlob && descBytes >= sizeof(wchar_t)) {
            size_t numChars = descBytes / sizeof(wchar_t);
            auto* pOutDesc = static_cast<wchar_t*>(win32::LocalAlloc(0x0040, (numChars + 1) * sizeof(wchar_t)));
            if (pOutDesc) {
                std::memcpy(pOutDesc, pDescInBlob, descBytes);
                pOutDesc[numChars] = L'\0';
                *ppszDataDescr = pOutDesc;
            } else {
                *ppszDataDescr = nullptr;
            }
        } else {
            *ppszDataDescr = nullptr;
        }
    }

    auto* outBuf = static_cast<uint8_t*>(win32::LocalAlloc(0x0040 /*LPTR*/, plaintext.size() + 1));
    if (!outBuf) {
        win32::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return win32::FALSE;
    }

    if (!plaintext.empty()) {
        std::memcpy(outBuf, plaintext.data(), plaintext.size());
    }
    outBuf[plaintext.size()] = 0;

    pDataOut->cbData = static_cast<uint32_t>(plaintext.size());
    pDataOut->pbData = outBuf;
    return win32::TRUE;
}

// ============================================================================
// 3. Base64 & Hex Conversion Engine
// ============================================================================

namespace detail {
    inline const char B64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    inline std::string EncodeBase64(const uint8_t* data, size_t len, bool noCrlf) {
        std::string out;
        out.reserve(((len + 2) / 3) * 4 + (len / 48) * 2);

        size_t lineCount = 0;
        for (size_t i = 0; i < len; i += 3) {
            uint32_t b0 = data[i];
            uint32_t b1 = (i + 1 < len) ? data[i + 1] : 0;
            uint32_t b2 = (i + 2 < len) ? data[i + 2] : 0;
            uint32_t triple = (b0 << 16) | (b1 << 8) | b2;

            out.push_back(B64_CHARS[(triple >> 18) & 0x3F]);
            out.push_back(B64_CHARS[(triple >> 12) & 0x3F]);
            out.push_back((i + 1 < len) ? B64_CHARS[(triple >> 6) & 0x3F] : '=');
            out.push_back((i + 2 < len) ? B64_CHARS[triple & 0x3F] : '=');

            lineCount += 4;
            if (!noCrlf && lineCount >= 64 && i + 3 < len) {
                out.push_back('\r');
                out.push_back('\n');
                lineCount = 0;
            }
        }
        if (!noCrlf) {
            out.push_back('\r');
            out.push_back('\n');
        }
        return out;
    }

    inline std::vector<uint8_t> DecodeBase64(std::string_view str) {
        std::vector<uint8_t> out;
        out.reserve(str.size() * 3 / 4);

        auto val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        };

        uint32_t buf = 0;
        int bits = 0;
        for (char c : str) {
            if (c == '=') break;
            int v = val(c);
            if (v < 0) continue; // skip whitespace or formatting
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
            }
        }
        return out;
    }

    inline std::string EncodeHex(const uint8_t* data, size_t len, bool spaced, bool raw) {
        std::ostringstream ss;
        for (size_t i = 0; i < len; ++i) {
            if (spaced && i > 0) ss << " ";
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        }
        if (!raw) ss << "\r\n";
        return ss.str();
    }

    inline std::vector<uint8_t> DecodeHex(std::string_view str) {
        std::vector<uint8_t> out;
        out.reserve(str.size() / 2);

        int highNibble = -1;
        for (char c : str) {
            int v = -1;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else {
                // Skip separators (whitespace, delimiters, newlines)
                continue;
            }

            if (highNibble < 0) {
                highNibble = v;
            } else {
                out.push_back(static_cast<uint8_t>((highNibble << 4) | v));
                highNibble = -1;
            }
        }
        return out;
    }
}

inline win32::BOOL CryptBinaryToStringA(
    const uint8_t* pbBinary,
    uint32_t       cbBinary,
    uint32_t       dwFlags,
    char*          pszString,
    uint32_t*      pcchString
) {
    if (!pbBinary || !pcchString) {
        win32::SetLastError(ERROR_INVALID_PARAMETER);
        return win32::FALSE;
    }

    bool noCrlf = (dwFlags & CRYPT_STRING_NOCRLF) != 0;
    uint32_t fmt = dwFlags & 0x000000FF;

    std::string res;
    if (fmt == CRYPT_STRING_BASE64HEADER) {
        res = "-----BEGIN CERTIFICATE-----\r\n";
        res += detail::EncodeBase64(pbBinary, cbBinary, false);
        res += "-----END CERTIFICATE-----\r\n";
    } else if (fmt == CRYPT_STRING_BASE64 || fmt == CRYPT_STRING_BASE64_ANY) {
        res = detail::EncodeBase64(pbBinary, cbBinary, noCrlf);
    } else if (fmt == CRYPT_STRING_HEX || fmt == CRYPT_STRING_HEXASCII) {
        res = detail::EncodeHex(pbBinary, cbBinary, true, noCrlf);
    } else if (fmt == CRYPT_STRING_HEXRAW) {
        res = detail::EncodeHex(pbBinary, cbBinary, false, true);
    } else {
        res = detail::EncodeBase64(pbBinary, cbBinary, noCrlf);
    }

    uint32_t requiredLen = static_cast<uint32_t>(res.size() + 1);
    if (!pszString) {
        *pcchString = requiredLen;
        return win32::TRUE;
    }

    if (*pcchString < requiredLen) {
        *pcchString = requiredLen;
        win32::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return win32::FALSE;
    }

    std::memcpy(pszString, res.c_str(), requiredLen);
    *pcchString = requiredLen - 1;
    return win32::TRUE;
}

inline win32::BOOL CryptBinaryToStringW(
    const uint8_t* pbBinary,
    uint32_t       cbBinary,
    uint32_t       dwFlags,
    wchar_t*       pszString,
    uint32_t*      pcchString
) {
    if (!pbBinary || !pcchString) {
        win32::SetLastError(ERROR_INVALID_PARAMETER);
        return win32::FALSE;
    }

    uint32_t cch = 0;
    if (!CryptBinaryToStringA(pbBinary, cbBinary, dwFlags, nullptr, &cch)) {
        return win32::FALSE;
    }

    if (!pszString) {
        *pcchString = cch;
        return win32::TRUE;
    }

    if (*pcchString < cch) {
        *pcchString = cch;
        win32::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return win32::FALSE;
    }

    std::vector<char> tmp(cch);
    CryptBinaryToStringA(pbBinary, cbBinary, dwFlags, tmp.data(), &cch);
    for (size_t i = 0; i < cch; ++i) {
        pszString[i] = static_cast<wchar_t>(tmp[i]);
    }
    *pcchString = cch;
    return win32::TRUE;
}

inline win32::BOOL CryptStringToBinaryA(
    const char* pszString,
    uint32_t    cchString,
    uint32_t    dwFlags,
    uint8_t*    pbBinary,
    uint32_t*   pcbBinary,
    uint32_t*   pdwSkip,
    uint32_t*   pdwFlags
) {
    if (!pszString || !pcbBinary) {
        win32::SetLastError(ERROR_INVALID_PARAMETER);
        return win32::FALSE;
    }

    std::string s = (cchString > 0) ? std::string(pszString, cchString) : std::string(pszString);

    uint32_t fmt = dwFlags & 0x000000FF;
    std::vector<uint8_t> decoded;
    uint32_t resolvedFlag = CRYPT_STRING_BASE64;

    bool isHex = (fmt == CRYPT_STRING_HEX || fmt == CRYPT_STRING_HEXASCII ||
                  fmt == CRYPT_STRING_HEXRAW || fmt == CRYPT_STRING_HEX_ANY ||
                  fmt == CRYPT_STRING_HEXADDR || fmt == CRYPT_STRING_HEXASCIIADDR);

    if (isHex) {
        decoded = detail::DecodeHex(s);
        resolvedFlag = fmt;
    } else {
        // Strip header and footer if present
        size_t headerPos = s.find("-----BEGIN");
        if (headerPos != std::string::npos) {
            size_t headerEnd = s.find("-----", headerPos + 10);
            if (headerEnd != std::string::npos) {
                headerEnd = s.find_first_not_of("-\r\n ", headerEnd + 5);
                if (headerEnd != std::string::npos) {
                    s = s.substr(headerEnd);
                }
            }
        }
        size_t footerPos = s.find("-----END");
        if (footerPos != std::string::npos) {
            s = s.substr(0, footerPos);
        }

        decoded = detail::DecodeBase64(s);
        resolvedFlag = CRYPT_STRING_BASE64;
    }

    uint32_t required = static_cast<uint32_t>(decoded.size());

    if (!pbBinary) {
        *pcbBinary = required;
        if (pdwSkip) *pdwSkip = 0;
        if (pdwFlags) *pdwFlags = resolvedFlag;
        return win32::TRUE;
    }

    if (*pcbBinary < required) {
        *pcbBinary = required;
        win32::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return win32::FALSE;
    }

    if (!decoded.empty()) {
        std::memcpy(pbBinary, decoded.data(), required);
    }
    *pcbBinary = required;
    if (pdwSkip) *pdwSkip = 0;
    if (pdwFlags) *pdwFlags = resolvedFlag;
    return win32::TRUE;
}

inline win32::BOOL CryptStringToBinaryW(
    const wchar_t* pszString,
    uint32_t       cchString,
    uint32_t       dwFlags,
    uint8_t*       pbBinary,
    uint32_t*      pcbBinary,
    uint32_t*      pdwSkip,
    uint32_t*      pdwFlags
) {
    if (!pszString) {
        win32::SetLastError(ERROR_INVALID_PARAMETER);
        return win32::FALSE;
    }

    std::string narrow;
    size_t len = (cchString > 0) ? cchString : wcslen(pszString);
    narrow.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        narrow.push_back(static_cast<char>(pszString[i]));
    }

    return CryptStringToBinaryA(narrow.c_str(), static_cast<uint32_t>(narrow.size()), dwFlags, pbBinary, pcbBinary, pdwSkip, pdwFlags);
}

// ============================================================================
// 4. X.509 Certificate & Store Subsystem
// ============================================================================

struct InternalCert {
    std::wstring subject;
    std::wstring issuer;
    std::wstring friendlyName;
    std::vector<uint8_t> serialNumber;
    std::vector<uint8_t> sha1Hash;
    std::vector<uint8_t> rawEncoded;
    win32::FILETIME notBefore{};
    win32::FILETIME notAfter{};
    uint32_t refCount{1};
};

class MemoryCertStore {
public:
    std::wstring storeName;
    std::vector<std::shared_ptr<InternalCert>> certs;
    std::mutex mutex;

    explicit MemoryCertStore(std::wstring_view name) : storeName(name) {
        // Pre-populate ROOT store with MicaNT sovereign root CA certificate
        if (storeName == L"ROOT" || storeName == L"Root") {
            auto ca = std::make_shared<InternalCert>();
            ca->subject = L"CN=MicaNT Sovereign Root Certification Authority, O=MicaNT Project, C=US";
            ca->issuer  = ca->subject;
            ca->friendlyName = L"MicaNT Sovereign Root CA";
            ca->serialNumber = { 0x01, 0x19, 0x88, 0xDE, 0xC0 };

            // Generate deterministic SHA1 thumbprint
            std::string ident = "MicaNT Sovereign Root CA 2026";
            ca->sha1Hash = crypto::Sha1::hash(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(ident.data()), ident.size()));

            ca->rawEncoded = {
                0x30, 0x82, 0x01, 0x0A, 0x30, 0x81, 0xB1, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x05, 0x01, 0x19,
                0x88, 0xDE, 0xC0, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
            };
            ca->notBefore.dwLowDateTime  = 0x00000000;
            ca->notBefore.dwHighDateTime = 0x01DA6000;
            ca->notAfter.dwLowDateTime   = 0xFFFFFFFF;
            ca->notAfter.dwHighDateTime  = 0x01E00000;

            certs.push_back(ca);
        }
    }
};

class CertStoreRegistry {
private:
    std::mutex m_mutex;
    std::unordered_map<std::wstring, std::shared_ptr<MemoryCertStore>> m_stores;

public:
    static CertStoreRegistry& Instance() {
        static CertStoreRegistry s_inst;
        return s_inst;
    }

    std::shared_ptr<MemoryCertStore> getStore(std::wstring_view name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::wstring s(name);
        for (auto& c : s) c = static_cast<wchar_t>(towupper(c));
        auto it = m_stores.find(s);
        if (it != m_stores.end()) {
            return it->second;
        }
        auto store = std::make_shared<MemoryCertStore>(s);
        m_stores[s] = store;
        return store;
    }
};

inline HCERTSTORE CertOpenSystemStoreW(uintptr_t /*hProv*/, const wchar_t* szSubsystemProtocol) {
    if (!szSubsystemProtocol) {
        win32::SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    auto store = CertStoreRegistry::Instance().getStore(szSubsystemProtocol);
    return static_cast<HCERTSTORE>(store.get());
}

inline HCERTSTORE CertOpenSystemStoreA(uintptr_t hProv, const char* szSubsystemProtocol) {
    if (!szSubsystemProtocol) {
        win32::SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    std::wstring wProto;
    while (*szSubsystemProtocol) wProto.push_back(*szSubsystemProtocol++);
    return CertOpenSystemStoreW(hProv, wProto.c_str());
}

inline HCERTSTORE CertOpenStore(
    uintptr_t lpszStoreProvider,
    [[maybe_unused]] uint32_t dwMsgAndCertEncodingType,
    [[maybe_unused]] uintptr_t hCryptProv,
    [[maybe_unused]] uint32_t dwFlags,
    const void* pvPara
) {
    if (lpszStoreProvider == CERT_STORE_PROV_SYSTEM_W && pvPara) {
        return CertOpenSystemStoreW(0, static_cast<const wchar_t*>(pvPara));
    }
    auto store = CertStoreRegistry::Instance().getStore(L"MEMORY");
    return static_cast<HCERTSTORE>(store.get());
}

inline win32::BOOL CertCloseStore([[maybe_unused]] HCERTSTORE hCertStore, [[maybe_unused]] uint32_t dwFlags) {
    return win32::TRUE;
}

inline PCCERT_CONTEXT CertCreateCertificateContext(
    uint32_t       dwCertEncodingType,
    const uint8_t* pbCertEncoded,
    uint32_t       cbCertEncoded
) {
    if (!pbCertEncoded || cbCertEncoded == 0) {
        win32::SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }

    auto* ctx = new CERT_CONTEXT{};
    ctx->dwCertEncodingType = dwCertEncodingType;
    ctx->cbCertEncoded = cbCertEncoded;
    ctx->pbCertEncoded = new uint8_t[cbCertEncoded];
    std::memcpy(ctx->pbCertEncoded, pbCertEncoded, cbCertEncoded);

    ctx->pCertInfo = new CERT_INFO{};
    ctx->pCertInfo->dwVersion = 2; // v3

    // Allocate internal representation
    auto* internal = new InternalCert{};
    internal->rawEncoded.assign(pbCertEncoded, pbCertEncoded + cbCertEncoded);
    internal->sha1Hash = crypto::Sha1::hash(std::span<const uint8_t>(pbCertEncoded, cbCertEncoded));
    internal->subject = L"CN=MicaNT Imported Certificate";
    internal->issuer  = L"CN=MicaNT Sovereign Authority";
    internal->friendlyName = L"MicaNT Test Certificate";

    ctx->pCertInfo->SerialNumber.cbData = 4;
    ctx->pCertInfo->SerialNumber.pbData = internal->sha1Hash.data();

    // Store internal pointer in reserved / handle slot
    ctx->hCertStore = reinterpret_cast<HCERTSTORE>(internal);

    return ctx;
}

inline PCCERT_CONTEXT CertDuplicateCertificateContext(PCCERT_CONTEXT pCertContext) {
    if (!pCertContext) return nullptr;
    auto* internal = reinterpret_cast<InternalCert*>(pCertContext->hCertStore);
    if (internal) {
        internal->refCount++;
    }
    return pCertContext;
}

inline win32::BOOL CertFreeCertificateContext(PCCERT_CONTEXT pCertContext) {
    if (!pCertContext) return win32::FALSE;
    auto* internal = reinterpret_cast<InternalCert*>(pCertContext->hCertStore);
    if (internal) {
        if (--internal->refCount == 0) {
            delete internal;
        }
    }
    delete[] pCertContext->pbCertEncoded;
    delete pCertContext->pCertInfo;
    delete pCertContext;
    return win32::TRUE;
}

inline PCCERT_CONTEXT CreateContextFromInternal(uint32_t dwCertEncodingType, const std::shared_ptr<InternalCert>& src) {
    if (!src) return nullptr;
    auto* ctx = new CERT_CONTEXT{};
    ctx->dwCertEncodingType = dwCertEncodingType;
    ctx->cbCertEncoded = static_cast<uint32_t>(src->rawEncoded.size());
    ctx->pbCertEncoded = new uint8_t[ctx->cbCertEncoded];
    if (ctx->cbCertEncoded > 0) {
        std::memcpy(ctx->pbCertEncoded, src->rawEncoded.data(), ctx->cbCertEncoded);
    }

    ctx->pCertInfo = new CERT_INFO{};
    ctx->pCertInfo->dwVersion = 2; // v3

    auto* internal = new InternalCert(*src);
    internal->refCount = 1;

    ctx->pCertInfo->SerialNumber.cbData = static_cast<uint32_t>(internal->serialNumber.size());
    ctx->pCertInfo->SerialNumber.pbData = internal->serialNumber.data();

    ctx->hCertStore = reinterpret_cast<HCERTSTORE>(internal);
    return ctx;
}

inline win32::BOOL CertAddCertificateContextToStore(
    HCERTSTORE     hCertStore,
    PCCERT_CONTEXT pCertContext,
    [[maybe_unused]] uint32_t dwAddDisposition,
    PCCERT_CONTEXT* ppStoreContext
) {
    if (!hCertStore || !pCertContext) {
        win32::SetLastError(ERROR_INVALID_PARAMETER);
        return win32::FALSE;
    }

    auto* store = reinterpret_cast<MemoryCertStore*>(hCertStore);
    std::lock_guard<std::mutex> lock(store->mutex);

    auto* internal = reinterpret_cast<InternalCert*>(pCertContext->hCertStore);
    auto entry = std::make_shared<InternalCert>();
    if (internal) {
        *entry = *internal;
    } else {
        entry->rawEncoded.assign(pCertContext->pbCertEncoded, pCertContext->pbCertEncoded + pCertContext->cbCertEncoded);
        entry->sha1Hash = crypto::Sha1::hash(entry->rawEncoded);
        entry->subject = L"CN=MicaNT Store Certificate";
    }
    entry->refCount = 1;

    store->certs.push_back(entry);

    if (ppStoreContext) {
        *ppStoreContext = CreateContextFromInternal(pCertContext->dwCertEncodingType, entry);
    }
    return win32::TRUE;
}

inline PCCERT_CONTEXT CertEnumCertificatesInStore(
    HCERTSTORE     hCertStore,
    PCCERT_CONTEXT pPrevCertContext
) {
    if (!hCertStore) return nullptr;
    auto* store = reinterpret_cast<MemoryCertStore*>(hCertStore);
    std::lock_guard<std::mutex> lock(store->mutex);

    if (store->certs.empty()) {
        if (pPrevCertContext) CertFreeCertificateContext(pPrevCertContext);
        win32::SetLastError(CRYPT_E_NOT_FOUND);
        return nullptr;
    }

    size_t nextIdx = 0;
    if (pPrevCertContext) {
        auto* prevInternal = reinterpret_cast<InternalCert*>(pPrevCertContext->hCertStore);
        for (size_t i = 0; i < store->certs.size(); ++i) {
            if (store->certs[i]->sha1Hash == prevInternal->sha1Hash) {
                nextIdx = i + 1;
                break;
            }
        }
        CertFreeCertificateContext(pPrevCertContext);
    }

    if (nextIdx >= store->certs.size()) {
        win32::SetLastError(CRYPT_E_NOT_FOUND);
        return nullptr;
    }

    const auto& c = store->certs[nextIdx];
    return CreateContextFromInternal(X509_ASN_ENCODING, c);
}

inline PCCERT_CONTEXT CertFindCertificateInStore(
    HCERTSTORE     hCertStore,
    uint32_t       dwCertEncodingType,
    uint32_t       /*dwFindFlags*/,
    uint32_t       dwFindType,
    const void*    pvFindPara,
    PCCERT_CONTEXT pPrevCertContext
) {
    if (!hCertStore) return nullptr;
    auto* store = reinterpret_cast<MemoryCertStore*>(hCertStore);
    std::lock_guard<std::mutex> lock(store->mutex);

    size_t startIdx = 0;
    if (pPrevCertContext) {
        auto* prevInternal = reinterpret_cast<InternalCert*>(pPrevCertContext->hCertStore);
        for (size_t i = 0; i < store->certs.size(); ++i) {
            if (store->certs[i]->sha1Hash == prevInternal->sha1Hash) {
                startIdx = i + 1;
                break;
            }
        }
        CertFreeCertificateContext(pPrevCertContext);
    }

    for (size_t i = startIdx; i < store->certs.size(); ++i) {
        const auto& c = store->certs[i];

        if (dwFindType == CERT_FIND_ANY) {
            return CreateContextFromInternal(dwCertEncodingType, c);
        } else if (dwFindType == CERT_FIND_SUBJECT_STR_W && pvFindPara) {
            std::wstring search(static_cast<const wchar_t*>(pvFindPara));
            if (c->subject.find(search) != std::wstring::npos || c->friendlyName.find(search) != std::wstring::npos) {
                return CreateContextFromInternal(dwCertEncodingType, c);
            }
        } else if (dwFindType == CERT_FIND_ISSUER_STR_W && pvFindPara) {
            std::wstring search(static_cast<const wchar_t*>(pvFindPara));
            if (c->issuer.find(search) != std::wstring::npos) {
                return CreateContextFromInternal(dwCertEncodingType, c);
            }
        } else if (dwFindType == CERT_FIND_SHA1_HASH && pvFindPara) {
            const auto* blob = static_cast<const DATA_BLOB*>(pvFindPara);
            if (blob && blob->cbData == 20 && std::memcmp(c->sha1Hash.data(), blob->pbData, 20) == 0) {
                return CreateContextFromInternal(dwCertEncodingType, c);
            }
        }
    }

    win32::SetLastError(CRYPT_E_NOT_FOUND);
    return nullptr;
}

inline uint32_t CertGetNameStringW(
    PCCERT_CONTEXT pCertContext,
    uint32_t       dwType,
    uint32_t       dwFlags,
    [[maybe_unused]] void* pvTypePara,
    wchar_t*       pszNameString,
    uint32_t       cchNameString
) {
    if (!pCertContext) return 0;
    auto* internal = reinterpret_cast<InternalCert*>(pCertContext->hCertStore);

    std::wstring name = L"MicaNT Certificate";
    if (internal) {
        if ((dwFlags & CERT_NAME_ISSUER_FLAG) != 0) {
            name = internal->issuer.empty() ? internal->subject : internal->issuer;
        } else if (dwType == CERT_NAME_FRIENDLY_DISPLAY_TYPE && !internal->friendlyName.empty()) {
            name = internal->friendlyName;
        } else if (!internal->subject.empty()) {
            name = internal->subject;
        }
    }

    uint32_t required = static_cast<uint32_t>(name.size() + 1);
    if (!pszNameString || cchNameString == 0) {
        return required;
    }

    uint32_t toCopy = std::min<uint32_t>(required, cchNameString);
    std::memcpy(pszNameString, name.c_str(), (toCopy - 1) * sizeof(wchar_t));
    pszNameString[toCopy - 1] = L'\0';
    return toCopy;
}

inline uint32_t CertGetNameStringA(
    PCCERT_CONTEXT pCertContext,
    uint32_t       dwType,
    uint32_t       dwFlags,
    void*          pvTypePara,
    char*          pszNameString,
    uint32_t       cchNameString
) {
    if (!pCertContext) return 0;
    uint32_t reqW = CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, nullptr, 0);
    std::vector<wchar_t> wBuf(reqW);
    CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, wBuf.data(), reqW);

    if (!pszNameString || cchNameString == 0) {
        return reqW;
    }

    uint32_t toCopy = std::min<uint32_t>(reqW, cchNameString);
    for (size_t i = 0; i < toCopy - 1; ++i) {
        pszNameString[i] = static_cast<char>(wBuf[i]);
    }
    pszNameString[toCopy - 1] = '\0';
    return toCopy;
}

inline win32::BOOL CertGetCertificateContextProperty(
    PCCERT_CONTEXT pCertContext,
    uint32_t       dwPropId,
    void*          pvData,
    uint32_t*      pcbData
) {
    if (!pCertContext || !pcbData) {
        win32::SetLastError(ERROR_INVALID_PARAMETER);
        return win32::FALSE;
    }

    auto* internal = reinterpret_cast<InternalCert*>(pCertContext->hCertStore);

    if (dwPropId == CERT_SHA1_HASH_PROP_ID) {
        uint32_t req = 20;
        if (!pvData) {
            *pcbData = req;
            return win32::TRUE;
        }
        if (*pcbData < req) {
            *pcbData = req;
            win32::SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return win32::FALSE;
        }
        if (internal && internal->sha1Hash.size() == 20) {
            std::memcpy(pvData, internal->sha1Hash.data(), 20);
        } else {
            auto hash = crypto::Sha1::hash(std::span<const uint8_t>(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded));
            std::memcpy(pvData, hash.data(), 20);
        }
        *pcbData = req;
        return win32::TRUE;
    }

    win32::SetLastError(CRYPT_E_NOT_FOUND);
    return win32::FALSE;
}

// ============================================================================
// 5. Subsystem Export Registration
// ============================================================================

inline void InitializeCrypt32SubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // Data Protection API (DPAPI)
    ldr.registerExport("crypt32.dll", "CryptProtectData", reinterpret_cast<void*>(CryptProtectData));
    ldr.registerExport("crypt32.dll", "CryptUnprotectData", reinterpret_cast<void*>(CryptUnprotectData));

    // String / Binary formatting
    ldr.registerExport("crypt32.dll", "CryptBinaryToStringA", reinterpret_cast<void*>(CryptBinaryToStringA));
    ldr.registerExport("crypt32.dll", "CryptBinaryToStringW", reinterpret_cast<void*>(CryptBinaryToStringW));
    ldr.registerExport("crypt32.dll", "CryptStringToBinaryA", reinterpret_cast<void*>(CryptStringToBinaryA));
    ldr.registerExport("crypt32.dll", "CryptStringToBinaryW", reinterpret_cast<void*>(CryptStringToBinaryW));

    // Certificate Stores
    ldr.registerExport("crypt32.dll", "CertOpenSystemStoreA", reinterpret_cast<void*>(CertOpenSystemStoreA));
    ldr.registerExport("crypt32.dll", "CertOpenSystemStoreW", reinterpret_cast<void*>(CertOpenSystemStoreW));
    ldr.registerExport("crypt32.dll", "CertOpenStore", reinterpret_cast<void*>(CertOpenStore));
    ldr.registerExport("crypt32.dll", "CertCloseStore", reinterpret_cast<void*>(CertCloseStore));
    ldr.registerExport("crypt32.dll", "CertCreateCertificateContext", reinterpret_cast<void*>(CertCreateCertificateContext));
    ldr.registerExport("crypt32.dll", "CertDuplicateCertificateContext", reinterpret_cast<void*>(CertDuplicateCertificateContext));
    ldr.registerExport("crypt32.dll", "CertFreeCertificateContext", reinterpret_cast<void*>(CertFreeCertificateContext));
    ldr.registerExport("crypt32.dll", "CertAddCertificateContextToStore", reinterpret_cast<void*>(CertAddCertificateContextToStore));
    ldr.registerExport("crypt32.dll", "CertEnumCertificatesInStore", reinterpret_cast<void*>(CertEnumCertificatesInStore));
    ldr.registerExport("crypt32.dll", "CertFindCertificateInStore", reinterpret_cast<void*>(CertFindCertificateInStore));
    ldr.registerExport("crypt32.dll", "CertGetNameStringA", reinterpret_cast<void*>(CertGetNameStringA));
    ldr.registerExport("crypt32.dll", "CertGetNameStringW", reinterpret_cast<void*>(CertGetNameStringW));
    ldr.registerExport("crypt32.dll", "CertGetCertificateContextProperty", reinterpret_cast<void*>(CertGetCertificateContextProperty));
}

} // namespace micant::crypt32
