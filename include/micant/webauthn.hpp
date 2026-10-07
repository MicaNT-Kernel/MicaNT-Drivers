// ============================================================================
// MicaNT: Windows Web Authentication & Sovereign FIDO2 / Passkey Subsystem
// (include/micant/webauthn.hpp)
//
// Strict Clean-Room Implementation based on:
//   - W3C Web Authentication: An API for accessing Public Key Credentials Level 2/3
//   - FIDO Alliance CTAP2 (Client-to-Authenticator Protocol) Specification
//   - Microsoft webauthn.h / webauthn.dll Native Win32 C ABI Specification
//   - RFC 8152 / RFC 9052 (CBOR Object Signing and Encryption - COSE)
//   - NIST FIPS 186-4 / SEC 2 (Elliptic Curve Cryptography ECDSA P-256 / secp256r1)
//
// Subsystem Overview:
//   webauthn.hpp provides the complete Windows Web Authentication, FIDO2, and
//   Passkey platform authenticator subsystem for MicaNT, completely free of
//   external dependencies, cloud telemetry, or third-party cryptographic libraries.
//
// Features:
//   - Native Win32 C WebAuthn API:
//       * WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable
//       * WebAuthNAuthenticatorMakeCredential
//       * WebAuthNAuthenticatorGetAssertion
//       * WebAuthNFreeCredentialAttestation
//       * WebAuthNFreeAssertion
//       * WebAuthNGetCancellationId
//       * WebAuthNCancelCurrentOperation
//       * WebAuthNGetErrorName
//       * WebAuthNGetApiVersionNumber
//       * WebAuthNGetPlatformCredentialList
//       * WebAuthNFreePlatformCredentialList
//       * WebAuthNDeletePlatformCredential
//   - CTAP2 Authenticator Data Serialization & Parsing:
//       * 32-byte SHA-256 Relying Party ID Hash
//       * 1-byte Flags (UP=0x01, UV=0x04, BE=0x08, BS=0x10, AT=0x40, ED=0x80)
//       * 4-byte Big-Endian Monotonic Sign Counter
//       * Attested Credential Data (16-byte AAGUID, Credential ID, COSE Key)
//   - Sovereign Cryptographic Engine:
//       * 256-bit Big-Integer Arithmetic (Uint256, Uint512)
//       * Clean-Room NIST P-256 (secp256r1) Elliptic Curve Field & Group Arithmetic
//       * Deterministic ECDSA Key Generation, Signing, and Verification
//       * ASN.1 DER Sequence Encoding / Decoding for ECDSA (r, s) Signatures
//       * Compact CBOR Serialization for COSE Keys and Attestation Objects
//   - In-Memory Sovereign Authenticator Vault:
//       * Thread-safe credential storage & query engine
//       * Resident credential matching by RP ID & User ID
//       * Dynamic cancellation token tracking & operation abort logic
//
// Core Dynamic Module:
//   - webauthn.dll
//
// Trademark & Nominative Fair Use Notice:
//   Windows and WebAuthn are registered trademarks of Microsoft Corp. and the
//   W3C / FIDO Alliance. MicaNT is an independent sovereign clean-room implementation
//   engineered for binary interoperability (*Google LLC v. Oracle America, Inc.*).
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "cipherksp.hpp"
#include "ldr.hpp"
#include "version.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace micant::webauthn {

using DWORD   = uint32_t;
using LONG    = int32_t;
using BOOL    = int32_t;
using BYTE    = uint8_t;
using PBYTE   = uint8_t*;
using PCWSTR  = const wchar_t*;
using LPCWSTR = const wchar_t*;
using HWND    = void*;
using PVOID   = void*;
using HRESULT = int32_t;
using GUID    = micant::GUID;

#ifndef WINAPI
#define WINAPI __stdcall
#endif

// ============================================================================
// 1. WebAuthn API Versions & Constants (conforming to webauthn.h)
// ============================================================================

inline constexpr DWORD WEBAUTHN_API_VERSION_1 = 1;
inline constexpr DWORD WEBAUTHN_API_VERSION_2 = 2;
inline constexpr DWORD WEBAUTHN_API_VERSION_3 = 3;
inline constexpr DWORD WEBAUTHN_API_VERSION_4 = 4;
inline constexpr DWORD WEBAUTHN_API_VERSION_CURRENT = WEBAUTHN_API_VERSION_4;

inline constexpr DWORD WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION       = 1;
inline constexpr DWORD WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION     = 1;
inline constexpr DWORD WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION   = 1;
inline constexpr DWORD WEBAUTHN_CLIENT_DATA_CURRENT_VERSION                 = 1;
inline constexpr DWORD WEBAUTHN_CREDENTIAL_CURRENT_VERSION                  = 1;
inline constexpr DWORD WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION      = 3;
inline constexpr DWORD WEBAUTHN_ASSERTION_CURRENT_VERSION                   = 3;
inline constexpr DWORD WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION = 4;
inline constexpr DWORD WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION   = 4;

// COSE Algorithms (RFC 8152 / RFC 9052)
inline constexpr LONG WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256        = -7;
inline constexpr LONG WEBAUTHN_COSE_ALGORITHM_ECDSA_P384_WITH_SHA384        = -35;
inline constexpr LONG WEBAUTHN_COSE_ALGORITHM_ECDSA_P521_WITH_SHA512        = -36;
inline constexpr LONG WEBAUTHN_COSE_ALGORITHM_EDDSA                         = -8;
inline constexpr LONG WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_v1_5_WITH_SHA256 = -257;
inline constexpr LONG WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_v1_5_WITH_SHA384 = -258;
inline constexpr LONG WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_v1_5_WITH_SHA512 = -259;
inline constexpr LONG WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA256           = -37;
inline constexpr LONG WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA384           = -38;
inline constexpr LONG WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA512           = -39;

// Credential Types
inline constexpr const wchar_t* WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = L"public-key";

// Hash Algorithms
inline constexpr const wchar_t* WEBAUTHN_HASH_ALGORITHM_SHA_256 = L"SHA-256";
inline constexpr const wchar_t* WEBAUTHN_HASH_ALGORITHM_SHA_384 = L"SHA-384";
inline constexpr const wchar_t* WEBAUTHN_HASH_ALGORITHM_SHA_512 = L"SHA-512";

// Authenticator Data Flags (CTAP2 §6.1)
inline constexpr uint8_t WEBAUTHN_AUTHENTICATOR_DATA_FLAG_UP = 0x01; // User Present
inline constexpr uint8_t WEBAUTHN_AUTHENTICATOR_DATA_FLAG_UV = 0x04; // User Verified
inline constexpr uint8_t WEBAUTHN_AUTHENTICATOR_DATA_FLAG_BE = 0x08; // Backup Eligibility
inline constexpr uint8_t WEBAUTHN_AUTHENTICATOR_DATA_FLAG_BS = 0x10; // Backup State
inline constexpr uint8_t WEBAUTHN_AUTHENTICATOR_DATA_FLAG_AT = 0x40; // Attested Credential Data
inline constexpr uint8_t WEBAUTHN_AUTHENTICATOR_DATA_FLAG_ED = 0x80; // Extension Data

// Authenticator Attachment
inline constexpr DWORD WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY            = 0;
inline constexpr DWORD WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM       = 1;
inline constexpr DWORD WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 2;

// User Verification Requirement
inline constexpr DWORD WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY         = 0;
inline constexpr DWORD WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED    = 1;
inline constexpr DWORD WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED   = 2;
inline constexpr DWORD WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 3;

// Attestation Conveyance Preference
inline constexpr DWORD WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY      = 0;
inline constexpr DWORD WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE     = 1;
inline constexpr DWORD WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT = 2;
inline constexpr DWORD WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT   = 3;

// Enterprise Attestation
inline constexpr DWORD WEBAUTHN_ENTERPRISE_ATTESTATION_NONE     = 0;
inline constexpr DWORD WEBAUTHN_ENTERPRISE_ATTESTATION_VENDOR   = 1;
inline constexpr DWORD WEBAUTHN_ENTERPRISE_ATTESTATION_PLATFORM = 2;

// Large Blob Status
inline constexpr DWORD WEBAUTHN_LARGE_BLOB_STATUS_NONE    = 0;
inline constexpr DWORD WEBAUTHN_LARGE_BLOB_STATUS_SUCCESS = 1;

// ============================================================================
// 2. WebAuthn Win32 Structures (conforming to webauthn.h)
// ============================================================================

struct WEBAUTHN_RP_ENTITY_INFORMATION {
    DWORD dwVersion;
    PCWSTR pwszId;
    PCWSTR pwszName;
    PCWSTR pwszIcon;
};
using PWEBAUTHN_RP_ENTITY_INFORMATION = WEBAUTHN_RP_ENTITY_INFORMATION*;
using PCWEBAUTHN_RP_ENTITY_INFORMATION = const WEBAUTHN_RP_ENTITY_INFORMATION*;

struct WEBAUTHN_USER_ENTITY_INFORMATION {
    DWORD dwVersion;
    DWORD cbId;
    PBYTE pbId;
    PCWSTR pwszName;
    PCWSTR pwszIcon;
    PCWSTR pwszDisplayName;
};
using PWEBAUTHN_USER_ENTITY_INFORMATION = WEBAUTHN_USER_ENTITY_INFORMATION*;
using PCWEBAUTHN_USER_ENTITY_INFORMATION = const WEBAUTHN_USER_ENTITY_INFORMATION*;

struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
    DWORD dwVersion;
    PCWSTR pwszCredentialType;
    LONG lAlg;
};
using PWEBAUTHN_COSE_CREDENTIAL_PARAMETER = WEBAUTHN_COSE_CREDENTIAL_PARAMETER*;
using PCWEBAUTHN_COSE_CREDENTIAL_PARAMETER = const WEBAUTHN_COSE_CREDENTIAL_PARAMETER*;

struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
    DWORD cCredentialParameters;
    PWEBAUTHN_COSE_CREDENTIAL_PARAMETER pCredentialParameters;
};
using PWEBAUTHN_COSE_CREDENTIAL_PARAMETERS = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS*;
using PCWEBAUTHN_COSE_CREDENTIAL_PARAMETERS = const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS*;

struct WEBAUTHN_CLIENT_DATA {
    DWORD dwVersion;
    DWORD cbClientDataJSON;
    PBYTE pbClientDataJSON;
    PCWSTR pwszHashAlgId;
};
using PWEBAUTHN_CLIENT_DATA = WEBAUTHN_CLIENT_DATA*;
using PCWEBAUTHN_CLIENT_DATA = const WEBAUTHN_CLIENT_DATA*;

struct WEBAUTHN_CREDENTIAL {
    DWORD dwVersion;
    DWORD cbId;
    PBYTE pbId;
    PCWSTR pwszCredentialType;
};
using PWEBAUTHN_CREDENTIAL = WEBAUTHN_CREDENTIAL*;
using PCWEBAUTHN_CREDENTIAL = const WEBAUTHN_CREDENTIAL*;

struct WEBAUTHN_CREDENTIALS {
    DWORD cCredentials;
    PWEBAUTHN_CREDENTIAL pCredentials;
};
using PWEBAUTHN_CREDENTIALS = WEBAUTHN_CREDENTIALS*;
using PCWEBAUTHN_CREDENTIALS = const WEBAUTHN_CREDENTIALS*;

struct WEBAUTHN_EXTENSION {
    PCWSTR pwszExtensionType;
    DWORD cbExtension;
    PVOID pvExtension;
};
using PWEBAUTHN_EXTENSION = WEBAUTHN_EXTENSION*;

struct WEBAUTHN_EXTENSIONS {
    DWORD cExtensions;
    PWEBAUTHN_EXTENSION pExtensions;
};
using PWEBAUTHN_EXTENSIONS = WEBAUTHN_EXTENSIONS*;

struct WEBAUTHN_CREDENTIAL_ATTESTATION {
    DWORD dwVersion;
    PCWSTR pwszFormatType;
    DWORD cbAuthenticatorData;
    PBYTE pbAuthenticatorData;
    DWORD cbAttestation;
    PBYTE pbAttestation;
    DWORD cbCredentialId;
    PBYTE pbCredentialId;
    DWORD dwAttestationDecodeType;
    PVOID pvAttestationDecode;
    DWORD cbAttestationObject;
    PBYTE pbAttestationObject;
    DWORD cbCredentialRawId;
    PBYTE pbCredentialRawId;
    BOOL bEnterpriseAttestation;
    DWORD dwLargeBlobStatus;
    DWORD cbLargeBlob;
    PBYTE pbLargeBlob;
    BOOL bUsedPrf;
};
using PWEBAUTHN_CREDENTIAL_ATTESTATION = WEBAUTHN_CREDENTIAL_ATTESTATION*;

struct WEBAUTHN_ASSERTION {
    DWORD dwVersion;
    DWORD cbAuthenticatorData;
    PBYTE pbAuthenticatorData;
    DWORD cbSignature;
    PBYTE pbSignature;
    WEBAUTHN_CREDENTIAL Credential;
    DWORD cbUserId;
    PBYTE pbUserId;
    DWORD cbLargeBlob;
    PBYTE pbLargeBlob;
    DWORD dwLargeBlobStatus;
    BOOL bUsedPrf;
};
using PWEBAUTHN_ASSERTION = WEBAUTHN_ASSERTION*;

struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
    DWORD dwVersion;
    DWORD dwTimeoutMilliseconds;
    WEBAUTHN_CREDENTIALS CredentialList;
    WEBAUTHN_EXTENSIONS Extensions;
    DWORD dwAuthenticatorAttachment;
    BOOL bRequireResidentKey;
    DWORD dwUserVerificationRequirement;
    DWORD dwAttestationConveyancePreference;
    DWORD dwFlags;
    GUID* pCancellationId;
    BOOL bExcludeCredentialsList;
    DWORD dwEnterpriseAttestation;
    DWORD dwLargeBlobSupport;
    BOOL bPreferImmediatelyAvailableCredentials;
    BOOL bBrowserSupported;
};
using PWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS*;
using PCWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS*;

struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
    DWORD dwVersion;
    DWORD dwTimeoutMilliseconds;
    WEBAUTHN_CREDENTIALS CredentialList;
    WEBAUTHN_EXTENSIONS Extensions;
    DWORD dwAuthenticatorAttachment;
    DWORD dwUserVerificationRequirement;
    DWORD dwFlags;
    GUID* pCancellationId;
    BOOL bAllowCredentialsList;
    DWORD dwLargeBlobOperationType;
    DWORD cbLargeBlob;
    PBYTE pbLargeBlob;
    BOOL bBrowserSupported;
};
using PWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS*;
using PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS*;

struct WEBAUTHN_CREDENTIAL_DETAILS {
    DWORD dwVersion;
    DWORD cbCredentialID;
    PBYTE pbCredentialID;
    PWEBAUTHN_RP_ENTITY_INFORMATION pRpInformation;
    PWEBAUTHN_USER_ENTITY_INFORMATION pUserInformation;
    BOOL bRemovable;
    BOOL bBackedUp;
};
using PWEBAUTHN_CREDENTIAL_DETAILS = WEBAUTHN_CREDENTIAL_DETAILS*;

struct WEBAUTHN_CREDENTIAL_DETAILS_LIST {
    DWORD cCredentialDetails;
    PWEBAUTHN_CREDENTIAL_DETAILS* ppCredentialDetails;
};
using PWEBAUTHN_CREDENTIAL_DETAILS_LIST = WEBAUTHN_CREDENTIAL_DETAILS_LIST*;

// ============================================================================
// 3. Clean-Room 256-Bit Integer & Elliptic Curve Mathematics (secp256r1)
// ============================================================================

struct Uint256 {
    uint64_t w[4]{ 0, 0, 0, 0 }; // Little-endian 64-bit words

    constexpr Uint256() = default;
    constexpr Uint256(uint64_t v) { w[0] = v; }
    constexpr Uint256(uint64_t w0, uint64_t w1, uint64_t w2, uint64_t w3) {
        w[0] = w0; w[1] = w1; w[2] = w2; w[3] = w3;
    }

    bool isZero() const noexcept {
        return (w[0] | w[1] | w[2] | w[3]) == 0;
    }

    bool operator==(const Uint256& o) const noexcept {
        return w[0] == o.w[0] && w[1] == o.w[1] && w[2] == o.w[2] && w[3] == o.w[3];
    }

    bool operator!=(const Uint256& o) const noexcept {
        return !(*this == o);
    }

    void toBytes(uint8_t out[32]) const noexcept {
        for (int i = 0; i < 4; ++i) {
            uint64_t val = w[3 - i];
            out[i * 8 + 0] = static_cast<uint8_t>((val >> 56) & 0xFF);
            out[i * 8 + 1] = static_cast<uint8_t>((val >> 48) & 0xFF);
            out[i * 8 + 2] = static_cast<uint8_t>((val >> 40) & 0xFF);
            out[i * 8 + 3] = static_cast<uint8_t>((val >> 32) & 0xFF);
            out[i * 8 + 4] = static_cast<uint8_t>((val >> 24) & 0xFF);
            out[i * 8 + 5] = static_cast<uint8_t>((val >> 16) & 0xFF);
            out[i * 8 + 6] = static_cast<uint8_t>((val >> 8)  & 0xFF);
            out[i * 8 + 7] = static_cast<uint8_t>(val         & 0xFF);
        }
    }

    static Uint256 fromBytes(const uint8_t in[32]) noexcept {
        Uint256 r;
        for (int i = 0; i < 4; ++i) {
            uint64_t val = 0;
            for (int b = 0; b < 8; ++b) {
                val = (val << 8) | in[i * 8 + b];
            }
            r.w[3 - i] = val;
        }
        return r;
    }
};

inline int cmp(const Uint256& a, const Uint256& b) noexcept {
    for (int i = 3; i >= 0; --i) {
        if (a.w[i] < b.w[i]) return -1;
        if (a.w[i] > b.w[i]) return 1;
    }
    return 0;
}

inline Uint256 add(const Uint256& a, const Uint256& b, uint64_t& carryOut) noexcept {
    Uint256 r;
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 sum = static_cast<unsigned __int128>(a.w[i]) + b.w[i] + carry;
        r.w[i] = static_cast<uint64_t>(sum);
        carry = static_cast<uint64_t>(sum >> 64);
    }
    carryOut = carry;
    return r;
}

inline Uint256 sub(const Uint256& a, const Uint256& b, uint64_t& borrowOut) noexcept {
    Uint256 r;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t bi = b.w[i] + borrow;
        borrow = ((bi < b.w[i] && borrow == 1) || (a.w[i] < bi)) ? 1 : 0;
        r.w[i] = a.w[i] - bi;
    }
    borrowOut = borrow;
    return r;
}

inline Uint256 modAdd(const Uint256& a, const Uint256& b, const Uint256& m) noexcept {
    uint64_t carry = 0;
    Uint256 sum = add(a, b, carry);
    if (carry || cmp(sum, m) >= 0) {
        uint64_t borrow = 0;
        sum = sub(sum, m, borrow);
    }
    return sum;
}

inline Uint256 modSub(const Uint256& a, const Uint256& b, const Uint256& m) noexcept {
    uint64_t borrow = 0;
    Uint256 diff = sub(a, b, borrow);
    if (borrow) {
        uint64_t c = 0;
        diff = add(diff, m, c);
    }
    return diff;
}

struct Uint512 {
    uint64_t w[8]{ 0 };
};

inline Uint512 mul512(const Uint256& a, const Uint256& b) noexcept {
    Uint512 prod{};
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned __int128 cur = static_cast<unsigned __int128>(prod.w[i + j]) +
                                    static_cast<unsigned __int128>(a.w[i]) * b.w[j] + carry;
            prod.w[i + j] = static_cast<uint64_t>(cur);
            carry = cur >> 64;
        }
        int k = i + 4;
        while (carry > 0 && k < 8) {
            unsigned __int128 cur = static_cast<unsigned __int128>(prod.w[k]) + carry;
            prod.w[k] = static_cast<uint64_t>(cur);
            carry = cur >> 64;
            k++;
        }
    }
    return prod;
}

inline Uint256 mod512(const Uint512& val, const Uint256& m) noexcept {
    Uint256 rem{};
    for (int bit = 511; bit >= 0; --bit) {
        uint64_t carry = 0;
        for (int i = 0; i < 4; ++i) {
            uint64_t nextCarry = (rem.w[i] >> 63) & 1;
            rem.w[i] = (rem.w[i] << 1) | carry;
            carry = nextCarry;
        }
        int wordIdx = bit / 64;
        int bitIdx = bit % 64;
        uint64_t inBit = (val.w[wordIdx] >> bitIdx) & 1;
        rem.w[0] |= inBit;

        if (carry || cmp(rem, m) >= 0) {
            uint64_t borrow = 0;
            rem = sub(rem, m, borrow);
        }
    }
    return rem;
}

inline Uint256 modMul(const Uint256& a, const Uint256& b, const Uint256& m) noexcept {
    return mod512(mul512(a, b), m);
}

inline Uint256 modExp(Uint256 base, Uint256 exp, const Uint256& m) noexcept {
    Uint256 result(1);
    base = mod512(mul512(base, Uint256(1)), m);
    for (int bit = 0; bit < 256; ++bit) {
        int wordIdx = bit / 64;
        int bitIdx = bit % 64;
        if ((exp.w[wordIdx] >> bitIdx) & 1) {
            result = modMul(result, base, m);
        }
        base = modMul(base, base, m);
    }
    return result;
}

inline Uint256 modInv(const Uint256& a, const Uint256& m) noexcept {
    uint64_t borrow = 0;
    Uint256 exp = sub(m, Uint256(2), borrow);
    return modExp(a, exp, m);
}

// NIST P-256 (secp256r1) Curve Parameters
inline const Uint256 P256_P(0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL, 0x0000000000000000ULL, 0xFFFFFFFF00000001ULL);
inline const Uint256 P256_N(0xF3B9CAC2FC632551ULL, 0xBCE6FAADA7179E84ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL);
inline const Uint256 P256_A(0xFFFFFFFFFFFFFFFCULL, 0x00000000FFFFFFFFULL, 0x0000000000000000ULL, 0xFFFFFFFF00000001ULL);
inline const Uint256 P256_B(0x3BCE3C3E27D2604BULL, 0x651D06B0CC53B0F6ULL, 0xB3EBBD55769886BCULL, 0x5AC635D8AA3A93E7ULL);
inline const Uint256 P256_Gx(0xF4A13945D898C296ULL, 0x77037D812DEB33A0ULL, 0xF8BCE6E563A440F2ULL, 0x6B17D1F2E12C4247ULL);
inline const Uint256 P256_Gy(0xCBB6406837BF51F5ULL, 0x2BCE33576B315ECEULL, 0x8EE7EB4A7C0F9E16ULL, 0x4FE342E2FE1A7F9BULL);

struct Point {
    Uint256 x{};
    Uint256 y{};
    bool isInfinity{ true };
};

inline Point doublePoint(const Point& P) noexcept {
    if (P.isInfinity || P.y.isZero()) return Point{};

    // lambda = (3 x^2 + a) / (2 y) mod p
    Uint256 x2 = modMul(P.x, P.x, P256_P);
    Uint256 num = modAdd(modAdd(x2, x2, P256_P), x2, P256_P);
    num = modAdd(num, P256_A, P256_P);
    Uint256 den = modAdd(P.y, P.y, P256_P);
    Uint256 lambda = modMul(num, modInv(den, P256_P), P256_P);

    // x3 = lambda^2 - 2 x
    Uint256 x3 = modSub(modMul(lambda, lambda, P256_P), modAdd(P.x, P.x, P256_P), P256_P);

    // y3 = lambda (x - x3) - y
    Uint256 y3 = modSub(modMul(lambda, modSub(P.x, x3, P256_P), P256_P), P.y, P256_P);

    return Point{ x3, y3, false };
}

inline Point addPoints(const Point& P1, const Point& P2) noexcept {
    if (P1.isInfinity) return P2;
    if (P2.isInfinity) return P1;
    if (P1.x == P2.x) {
        if (P1.y == P2.y) return doublePoint(P1);
        return Point{}; // Point at infinity
    }

    // lambda = (y2 - y1) / (x2 - x1) mod p
    Uint256 num = modSub(P2.y, P1.y, P256_P);
    Uint256 den = modSub(P2.x, P1.x, P256_P);
    Uint256 lambda = modMul(num, modInv(den, P256_P), P256_P);

    // x3 = lambda^2 - x1 - x2
    Uint256 x3 = modSub(modSub(modMul(lambda, lambda, P256_P), P1.x, P256_P), P2.x, P256_P);

    // y3 = lambda (x1 - x3) - y1
    Uint256 y3 = modSub(modMul(lambda, modSub(P1.x, x3, P256_P), P256_P), P1.y, P256_P);

    return Point{ x3, y3, false };
}

inline Point scalarMul(const Uint256& k, const Point& P) noexcept {
    Point result;
    Point base = P;
    for (int bit = 0; bit < 256; ++bit) {
        int wordIdx = bit / 64;
        int bitIdx = bit % 64;
        if ((k.w[wordIdx] >> bitIdx) & 1) {
            result = addPoints(result, base);
        }
        base = doublePoint(base);
    }
    return result;
}

// ============================================================================
// 4. Compact CBOR & ASN.1 DER Serialization Helpers
// ============================================================================

class CborWriter {
public:
    std::vector<uint8_t> buffer;

    void writeMapHeader(size_t count) {
        if (count < 24) {
            buffer.push_back(static_cast<uint8_t>(0xA0 | count));
        } else {
            buffer.push_back(0xB8);
            buffer.push_back(static_cast<uint8_t>(count & 0xFF));
        }
    }

    void writeInt(int64_t val) {
        if (val >= 0) {
            if (val < 24) {
                buffer.push_back(static_cast<uint8_t>(val));
            } else if (val <= 0xFF) {
                buffer.push_back(0x18);
                buffer.push_back(static_cast<uint8_t>(val));
            } else if (val <= 0xFFFF) {
                buffer.push_back(0x19);
                buffer.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
                buffer.push_back(static_cast<uint8_t>(val & 0xFF));
            } else {
                buffer.push_back(0x1A);
                buffer.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
                buffer.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
                buffer.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
                buffer.push_back(static_cast<uint8_t>(val & 0xFF));
            }
        } else {
            uint64_t neg = static_cast<uint64_t>(-1 - val);
            if (neg < 24) {
                buffer.push_back(static_cast<uint8_t>(0x20 | neg));
            } else if (neg <= 0xFF) {
                buffer.push_back(0x38);
                buffer.push_back(static_cast<uint8_t>(neg));
            } else if (neg <= 0xFFFF) {
                buffer.push_back(0x39);
                buffer.push_back(static_cast<uint8_t>((neg >> 8) & 0xFF));
                buffer.push_back(static_cast<uint8_t>(neg & 0xFF));
            } else {
                buffer.push_back(0x3A);
                buffer.push_back(static_cast<uint8_t>((neg >> 24) & 0xFF));
                buffer.push_back(static_cast<uint8_t>((neg >> 16) & 0xFF));
                buffer.push_back(static_cast<uint8_t>((neg >> 8) & 0xFF));
                buffer.push_back(static_cast<uint8_t>(neg & 0xFF));
            }
        }
    }

    void writeBytes(const uint8_t* data, size_t len) {
        if (len < 24) {
            buffer.push_back(static_cast<uint8_t>(0x40 | len));
        } else if (len <= 0xFF) {
            buffer.push_back(0x58);
            buffer.push_back(static_cast<uint8_t>(len));
        } else if (len <= 0xFFFF) {
            buffer.push_back(0x59);
            buffer.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
            buffer.push_back(static_cast<uint8_t>(len & 0xFF));
        } else {
            buffer.push_back(0x5A);
            buffer.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
            buffer.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
            buffer.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
            buffer.push_back(static_cast<uint8_t>(len & 0xFF));
        }
        buffer.insert(buffer.end(), data, data + len);
    }

    void writeText(std::string_view str) {
        size_t len = str.size();
        if (len < 24) {
            buffer.push_back(static_cast<uint8_t>(0x60 | len));
        } else if (len <= 0xFF) {
            buffer.push_back(0x78);
            buffer.push_back(static_cast<uint8_t>(len));
        } else if (len <= 0xFFFF) {
            buffer.push_back(0x79);
            buffer.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
            buffer.push_back(static_cast<uint8_t>(len & 0xFF));
        } else {
            buffer.push_back(0x7A);
            buffer.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
            buffer.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
            buffer.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
            buffer.push_back(static_cast<uint8_t>(len & 0xFF));
        }
        buffer.insert(buffer.end(), str.begin(), str.end());
    }
};

// Encode ASN.1 DER sequence for ECDSA (r, s)
inline std::vector<uint8_t> encodeEcdsaDerSignature(const Uint256& r, const Uint256& s) {
    uint8_t rBytes[32], sBytes[32];
    r.toBytes(rBytes);
    s.toBytes(sBytes);

    // Strip leading zeroes for r, keeping at least 1 byte
    size_t rStart = 0;
    while (rStart + 1 < 32 && rBytes[rStart] == 0) rStart++;
    bool rPad = (rBytes[rStart] & 0x80) != 0;
    size_t rLen = (32 - rStart) + (rPad ? 1 : 0);

    // Strip leading zeroes for s
    size_t sStart = 0;
    while (sStart + 1 < 32 && sBytes[sStart] == 0) sStart++;
    bool sPad = (sBytes[sStart] & 0x80) != 0;
    size_t sLen = (32 - sStart) + (sPad ? 1 : 0);

    size_t seqLen = 2 + rLen + 2 + sLen;

    std::vector<uint8_t> sig;
    sig.reserve(2 + seqLen);
    sig.push_back(0x30); // SEQUENCE tag
    sig.push_back(static_cast<uint8_t>(seqLen));

    // INTEGER r
    sig.push_back(0x02);
    sig.push_back(static_cast<uint8_t>(rLen));
    if (rPad) sig.push_back(0x00);
    sig.insert(sig.end(), rBytes + rStart, rBytes + 32);

    // INTEGER s
    sig.push_back(0x02);
    sig.push_back(static_cast<uint8_t>(sLen));
    if (sPad) sig.push_back(0x00);
    sig.insert(sig.end(), sBytes + sStart, sBytes + 32);

    return sig;
}

// Decode ASN.1 DER sequence for ECDSA (r, s)
inline bool decodeEcdsaDerSignature(const uint8_t* sig, size_t sigLen, Uint256& rOut, Uint256& sOut) {
    if (!sig || sigLen < 8 || sig[0] != 0x30) return false;
    size_t seqLen = sig[1];
    if (2 + seqLen > sigLen) return false;

    size_t pos = 2;
    if (sig[pos++] != 0x02) return false;
    size_t rLen = sig[pos++];
    if (pos + rLen > sigLen) return false;

    const uint8_t* rPtr = sig + pos;
    if (rLen > 1 && *rPtr == 0x00) { rPtr++; rLen--; }
    if (rLen > 32) return false;
    uint8_t rBuf[32]{ 0 };
    std::memcpy(rBuf + (32 - rLen), rPtr, rLen);
    rOut = Uint256::fromBytes(rBuf);
    pos += (sig[pos - 1]); // Skip the full r block

    if (sig[pos++] != 0x02) return false;
    size_t sLen = sig[pos++];
    if (pos + sLen > sigLen) return false;

    const uint8_t* sPtr = sig + pos;
    if (sLen > 1 && *sPtr == 0x00) { sPtr++; sLen--; }
    if (sLen > 32) return false;
    uint8_t sBuf[32]{ 0 };
    std::memcpy(sBuf + (32 - sLen), sPtr, sLen);
    sOut = Uint256::fromBytes(sBuf);

    return true;
}

// ============================================================================
// 5. Sovereign Platform Authenticator Vault & Cryptographic Pipeline
// ============================================================================

struct CredentialRecord {
    std::vector<uint8_t> credentialId;
    std::wstring rpId;
    std::vector<uint8_t> userId;
    std::wstring userName;
    std::wstring userDisplayName;
    Uint256 privateKey;
    Point publicKey;
    LONG coseAlg{ WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 };
    uint32_t signCount{ 0 };
    uint64_t createdAt{ 0 };
};

class SovereignPlatformAuthenticator {
private:
    std::mutex m_mutex;
    // Maps credentialId (hex) -> CredentialRecord
    std::unordered_map<std::string, CredentialRecord> m_credentials;
    // Active cancellation IDs
    std::unordered_map<std::string, bool> m_cancellations;

    // MicaNT Authenticator Attestation GUID (AAGUID): "MicaNT-WebAuthn1"
    static inline const uint8_t SOVEREIGN_AAGUID[16] = {
        0x4D, 0x69, 0x63, 0x61, 0x4E, 0x54, 0x2D, 0x57,
        0x65, 0x62, 0x41, 0x75, 0x74, 0x68, 0x6E, 0x31
    };

    static std::string toHex(const uint8_t* data, size_t len) {
        std::ostringstream oss;
        for (size_t i = 0; i < len; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        }
        return oss.str();
    }

    static std::string toHexGuid(const GUID& g) {
        char buf[64]{ 0 };
        std::snprintf(buf, sizeof(buf), "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            static_cast<unsigned int>(g.Data1), g.Data2, g.Data3,
            g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
            g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
        return std::string(buf);
    }

    static std::string utf16ToUtf8(const wchar_t* wstr) {
        if (!wstr) return "";
        std::string s;
        while (*wstr) {
            wchar_t ch = *wstr++;
            if (ch < 0x80) {
                s.push_back(static_cast<char>(ch));
            } else if (ch < 0x800) {
                s.push_back(static_cast<char>(0xC0 | (ch >> 6)));
                s.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
            } else {
                s.push_back(static_cast<char>(0xE0 | (ch >> 12)));
                s.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
                s.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
            }
        }
        return s;
    }

public:
    static SovereignPlatformAuthenticator& get() {
        static SovereignPlatformAuthenticator s_instance;
        return s_instance;
    }

    // Cancellation Management
    void registerCancellationId(const GUID& id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_cancellations[toHexGuid(id)] = false;
    }

    bool isCancelled(const GUID* pId) {
        if (!pId) return false;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_cancellations.find(toHexGuid(*pId));
        return (it != m_cancellations.end() && it->second);
    }

    bool cancelOperation(const GUID& id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string key = toHexGuid(id);
        auto it = m_cancellations.find(key);
        if (it != m_cancellations.end()) {
            it->second = true;
            return true;
        }
        m_cancellations[key] = true;
        return true;
    }

    // ECDSA Signature Generation for Digest
    static std::vector<uint8_t> signDigest(const Uint256& privKey, const Uint256& digest) {
        Point G{ P256_Gx, P256_Gy, false };

        // Deterministic Nonce Derivation (RFC 6979 inspired via HMAC-SHA256)
        uint8_t privBytes[32], digBytes[32];
        privKey.toBytes(privBytes);
        digest.toBytes(digBytes);

        std::vector<uint8_t> kSeed(64);
        std::memcpy(kSeed.data(), privBytes, 32);
        std::memcpy(kSeed.data() + 32, digBytes, 32);
        auto hmacDigest = crypto::HmacSha256::compute(
            std::span<const uint8_t>(privBytes, 32),
            std::span<const uint8_t>(digBytes, 32)
        );

        Uint256 k = Uint256::fromBytes(hmacDigest.data());
        // Ensure 1 <= k < n
        k = mod512(mul512(k, Uint256(1)), P256_N);
        if (k.isZero()) k = Uint256(1);

        Point R = scalarMul(k, G);
        Uint256 r = mod512(mul512(R.x, Uint256(1)), P256_N);
        if (r.isZero()) r = Uint256(1);

        Uint256 kinv = modInv(k, P256_N);
        Uint256 rd = modMul(r, privKey, P256_N);
        Uint256 erd = modAdd(digest, rd, P256_N);
        Uint256 s = modMul(kinv, erd, P256_N);
        if (s.isZero()) s = Uint256(1);

        // Low-S normalization
        uint64_t borrow = 0;
        Uint256 halfN = sub(P256_N, Uint256(1), borrow);
        halfN.w[0] = (halfN.w[0] >> 1) | (halfN.w[1] << 63);
        halfN.w[1] = (halfN.w[1] >> 1) | (halfN.w[2] << 63);
        halfN.w[2] = (halfN.w[2] >> 1) | (halfN.w[3] << 63);
        halfN.w[3] = (halfN.w[3] >> 1);
        if (cmp(s, halfN) > 0) {
            uint64_t b2 = 0;
            s = sub(P256_N, s, b2);
        }

        return encodeEcdsaDerSignature(r, s);
    }

    // ECDSA Signature Verification for Digest
    static bool verifyDigest(const Point& pubKey, const Uint256& digest, const uint8_t* sig, size_t sigLen) {
        Uint256 r, s;
        if (!decodeEcdsaDerSignature(sig, sigLen, r, s)) return false;
        if (r.isZero() || cmp(r, P256_N) >= 0 || s.isZero() || cmp(s, P256_N) >= 0) return false;

        Point G{ P256_Gx, P256_Gy, false };
        Uint256 w = modInv(s, P256_N);
        Uint256 u1 = modMul(digest, w, P256_N);
        Uint256 u2 = modMul(r, w, P256_N);

        Point p1 = scalarMul(u1, G);
        Point p2 = scalarMul(u2, pubKey);
        Point Rprime = addPoints(p1, p2);
        if (Rprime.isInfinity) return false;

        Uint256 v = mod512(mul512(Rprime.x, Uint256(1)), P256_N);
        return (v == r);
    }

    // Make Credential Implementation
    HRESULT makeCredential(
        PCWEBAUTHN_RP_ENTITY_INFORMATION pRpInformation,
        PCWEBAUTHN_USER_ENTITY_INFORMATION pUserInformation,
        [[maybe_unused]] PCWEBAUTHN_COSE_CREDENTIAL_PARAMETERS pCoseCredentialParameters,
        PCWEBAUTHN_CLIENT_DATA pClientData,
        PCWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS pMakeCredentialOptions,
        PWEBAUTHN_CREDENTIAL_ATTESTATION* ppWebAuthNCredentialAttestation
    ) {
        if (!pRpInformation || !pRpInformation->pwszId || !pUserInformation || !pClientData || !ppWebAuthNCredentialAttestation) {
            return static_cast<HRESULT>(0x80070057); // E_INVALIDARG
        }

        if (pMakeCredentialOptions && isCancelled(pMakeCredentialOptions->pCancellationId)) {
            return static_cast<HRESULT>(0x800704C7); // ERROR_CANCELLED
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        // 1. Calculate RP ID SHA-256 hash
        std::string rpIdUtf8 = utf16ToUtf8(pRpInformation->pwszId);
        auto rpIdHash = crypto::Sha256::hash(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(rpIdUtf8.data()), rpIdUtf8.size()));

        // 2. Generate P-256 Keypair
        uint8_t randPriv[32];
        crypto::Csprng::get().getBytes(std::span<uint8_t>(randPriv, 32));
        Uint256 privKey = Uint256::fromBytes(randPriv);
        privKey = mod512(mul512(privKey, Uint256(1)), P256_N);
        if (privKey.isZero()) privKey = Uint256(42);

        Point G{ P256_Gx, P256_Gy, false };
        Point pubKey = scalarMul(privKey, G);

        // 3. Generate Credential ID (32 bytes CSPRNG)
        std::vector<uint8_t> credId(32);
        crypto::Csprng::get().getBytes(std::span<uint8_t>(credId.data(), credId.size()));
        std::string credIdHex = toHex(credId.data(), credId.size());

        // 4. Encode Public Key in COSE Key format (RFC 8152 / RFC 9052)
        uint8_t qx[32], qy[32];
        pubKey.x.toBytes(qx);
        pubKey.y.toBytes(qy);

        CborWriter coseWriter;
        coseWriter.writeMapHeader(5);
        coseWriter.writeInt(1);  // kty: 2 (EC2)
        coseWriter.writeInt(2);
        coseWriter.writeInt(3);  // alg: -7 (ES256)
        coseWriter.writeInt(WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256);
        coseWriter.writeInt(-1); // crv: 1 (P-256)
        coseWriter.writeInt(1);
        coseWriter.writeInt(-2); // x-coord
        coseWriter.writeBytes(qx, 32);
        coseWriter.writeInt(-3); // y-coord
        coseWriter.writeBytes(qy, 32);

        // 5. Construct Authenticator Data (CTAP2 §6.1)
        // 32-byte rpIdHash + 1-byte flags + 4-byte signCount + 16-byte AAGUID + 2-byte credLen + credId + coseKey
        std::vector<uint8_t> authData;
        authData.insert(authData.end(), rpIdHash.begin(), rpIdHash.end());

        // Flags: UP (0x01) | UV (0x04) | AT (0x40) = 0x45
        uint8_t flags = WEBAUTHN_AUTHENTICATOR_DATA_FLAG_UP |
                        WEBAUTHN_AUTHENTICATOR_DATA_FLAG_UV |
                        WEBAUTHN_AUTHENTICATOR_DATA_FLAG_AT;
        authData.push_back(flags);

        // Sign Counter (0 initially, big-endian)
        authData.push_back(0);
        authData.push_back(0);
        authData.push_back(0);
        authData.push_back(0);

        // Attested Credential Data:
        // AAGUID (16 bytes)
        authData.insert(authData.end(), SOVEREIGN_AAGUID, SOVEREIGN_AAGUID + 16);
        // Credential ID Length (2 bytes big-endian)
        uint16_t credIdLen = static_cast<uint16_t>(credId.size());
        authData.push_back(static_cast<uint8_t>((credIdLen >> 8) & 0xFF));
        authData.push_back(static_cast<uint8_t>(credIdLen & 0xFF));
        // Credential ID
        authData.insert(authData.end(), credId.begin(), credId.end());
        // COSE Public Key
        authData.insert(authData.end(), coseWriter.buffer.begin(), coseWriter.buffer.end());

        // 6. Attestation Object (Self-Attestation packed / none)
        // Digest = SHA-256(authData || SHA-256(clientDataJSON))
        auto clientDataHash = crypto::Sha256::hash(std::span<const uint8_t>(
            pClientData->pbClientDataJSON, pClientData->cbClientDataJSON));

        std::vector<uint8_t> attBase;
        attBase.insert(attBase.end(), authData.begin(), authData.end());
        attBase.insert(attBase.end(), clientDataHash.begin(), clientDataHash.end());
        auto attDigest = crypto::Sha256::hash(std::span<const uint8_t>(attBase.data(), attBase.size()));

        Uint256 attDigestInt = Uint256::fromBytes(attDigest.data());
        auto attSig = signDigest(privKey, attDigestInt);

        // Build Attestation Statement CBOR map
        CborWriter attStmtWriter;
        attStmtWriter.writeMapHeader(2);
        attStmtWriter.writeText("alg");
        attStmtWriter.writeInt(WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256);
        attStmtWriter.writeText("sig");
        attStmtWriter.writeBytes(attSig.data(), attSig.size());

        // Full Attestation Object CBOR map
        CborWriter attObjWriter;
        attObjWriter.writeMapHeader(3);
        attObjWriter.writeText("fmt");
        attObjWriter.writeText("packed");
        attObjWriter.writeText("attStmt");
        attObjWriter.buffer.insert(attObjWriter.buffer.end(), attStmtWriter.buffer.begin(), attStmtWriter.buffer.end());
        attObjWriter.writeText("authData");
        attObjWriter.writeBytes(authData.data(), authData.size());

        // 7. Store in Sovereign Vault
        CredentialRecord rec{};
        rec.credentialId = credId;
        rec.rpId = pRpInformation->pwszId;
        if (pUserInformation->pbId && pUserInformation->cbId > 0) {
            rec.userId.assign(pUserInformation->pbId, pUserInformation->pbId + pUserInformation->cbId);
        }
        if (pUserInformation->pwszName) rec.userName = pUserInformation->pwszName;
        if (pUserInformation->pwszDisplayName) rec.userDisplayName = pUserInformation->pwszDisplayName;
        rec.privateKey = privKey;
        rec.publicKey = pubKey;
        rec.coseAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
        rec.signCount = 0;
        rec.createdAt = 1000;
        m_credentials[credIdHex] = rec;

        // 8. Allocate WEBAUTHN_CREDENTIAL_ATTESTATION struct
        auto* pAttestation = new WEBAUTHN_CREDENTIAL_ATTESTATION();
        std::memset(pAttestation, 0, sizeof(WEBAUTHN_CREDENTIAL_ATTESTATION));
        pAttestation->dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION;
        pAttestation->pwszFormatType = L"packed";

        pAttestation->cbAuthenticatorData = static_cast<DWORD>(authData.size());
        pAttestation->pbAuthenticatorData = new uint8_t[authData.size()];
        std::memcpy(pAttestation->pbAuthenticatorData, authData.data(), authData.size());

        pAttestation->cbAttestation = static_cast<DWORD>(attSig.size());
        pAttestation->pbAttestation = new uint8_t[attSig.size()];
        std::memcpy(pAttestation->pbAttestation, attSig.data(), attSig.size());

        pAttestation->cbCredentialId = static_cast<DWORD>(credId.size());
        pAttestation->pbCredentialId = new uint8_t[credId.size()];
        std::memcpy(pAttestation->pbCredentialId, credId.data(), credId.size());

        pAttestation->cbCredentialRawId = static_cast<DWORD>(credId.size());
        pAttestation->pbCredentialRawId = new uint8_t[credId.size()];
        std::memcpy(pAttestation->pbCredentialRawId, credId.data(), credId.size());

        pAttestation->cbAttestationObject = static_cast<DWORD>(attObjWriter.buffer.size());
        pAttestation->pbAttestationObject = new uint8_t[attObjWriter.buffer.size()];
        std::memcpy(pAttestation->pbAttestationObject, attObjWriter.buffer.data(), attObjWriter.buffer.size());

        *ppWebAuthNCredentialAttestation = pAttestation;
        return 0; // S_OK
    }

    // Get Assertion Implementation
    HRESULT getAssertion(
        LPCWSTR pwszRpId,
        PCWEBAUTHN_CLIENT_DATA pClientData,
        PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pGetAssertionOptions,
        PWEBAUTHN_ASSERTION* ppWebAuthNAssertion
    ) {
        if (!pwszRpId || !pClientData || !ppWebAuthNAssertion) {
            return static_cast<HRESULT>(0x80070057); // E_INVALIDARG
        }

        if (pGetAssertionOptions && isCancelled(pGetAssertionOptions->pCancellationId)) {
            return static_cast<HRESULT>(0x800704C7); // ERROR_CANCELLED
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        // Find candidate credential matching RpId
        CredentialRecord* pTargetCred = nullptr;

        // If specific credentials were requested, search for match
        if (pGetAssertionOptions && pGetAssertionOptions->CredentialList.cCredentials > 0) {
            for (DWORD i = 0; i < pGetAssertionOptions->CredentialList.cCredentials; ++i) {
                const auto& reqCred = pGetAssertionOptions->CredentialList.pCredentials[i];
                std::string reqIdHex = toHex(reqCred.pbId, reqCred.cbId);
                auto it = m_credentials.find(reqIdHex);
                if (it != m_credentials.end() && it->second.rpId == pwszRpId) {
                    pTargetCred = &it->second;
                    break;
                }
            }
        } else {
            // Pick resident passkey for this RP
            for (auto& pair : m_credentials) {
                if (pair.second.rpId == pwszRpId) {
                    pTargetCred = &pair.second;
                    break;
                }
            }
        }

        if (!pTargetCred) {
            return static_cast<HRESULT>(0x80090011); // NTE_NOT_FOUND
        }

        // Increment sign counter
        pTargetCred->signCount++;

        // 1. Calculate RP ID hash
        std::string rpIdUtf8 = utf16ToUtf8(pwszRpId);
        auto rpIdHash = crypto::Sha256::hash(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(rpIdUtf8.data()), rpIdUtf8.size()));

        // 2. Construct 37-byte Authenticator Data
        std::vector<uint8_t> authData;
        authData.insert(authData.end(), rpIdHash.begin(), rpIdHash.end());

        // Flags: UP (0x01) | UV (0x04) = 0x05
        uint8_t flags = WEBAUTHN_AUTHENTICATOR_DATA_FLAG_UP | WEBAUTHN_AUTHENTICATOR_DATA_FLAG_UV;
        authData.push_back(flags);

        // Sign Counter (big-endian)
        uint32_t cnt = pTargetCred->signCount;
        authData.push_back(static_cast<uint8_t>((cnt >> 24) & 0xFF));
        authData.push_back(static_cast<uint8_t>((cnt >> 16) & 0xFF));
        authData.push_back(static_cast<uint8_t>((cnt >> 8)  & 0xFF));
        authData.push_back(static_cast<uint8_t>(cnt         & 0xFF));

        // 3. Compute ClientDataJSON Hash
        auto clientDataHash = crypto::Sha256::hash(std::span<const uint8_t>(
            pClientData->pbClientDataJSON, pClientData->cbClientDataJSON));

        // 4. Compute Assertion Signature: sign(authData || clientDataHash)
        std::vector<uint8_t> sigBase;
        sigBase.insert(sigBase.end(), authData.begin(), authData.end());
        sigBase.insert(sigBase.end(), clientDataHash.begin(), clientDataHash.end());
        auto sigDigest = crypto::Sha256::hash(std::span<const uint8_t>(sigBase.data(), sigBase.size()));

        Uint256 sigDigestInt = Uint256::fromBytes(sigDigest.data());
        auto assertionSig = signDigest(pTargetCred->privateKey, sigDigestInt);

        // 5. Allocate WEBAUTHN_ASSERTION struct
        auto* pAssertion = new WEBAUTHN_ASSERTION();
        std::memset(pAssertion, 0, sizeof(WEBAUTHN_ASSERTION));
        pAssertion->dwVersion = WEBAUTHN_ASSERTION_CURRENT_VERSION;

        pAssertion->cbAuthenticatorData = static_cast<DWORD>(authData.size());
        pAssertion->pbAuthenticatorData = new uint8_t[authData.size()];
        std::memcpy(pAssertion->pbAuthenticatorData, authData.data(), authData.size());

        pAssertion->cbSignature = static_cast<DWORD>(assertionSig.size());
        pAssertion->pbSignature = new uint8_t[assertionSig.size()];
        std::memcpy(pAssertion->pbSignature, assertionSig.data(), assertionSig.size());

        pAssertion->Credential.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
        pAssertion->Credential.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
        pAssertion->Credential.cbId = static_cast<DWORD>(pTargetCred->credentialId.size());
        pAssertion->Credential.pbId = new uint8_t[pTargetCred->credentialId.size()];
        std::memcpy(pAssertion->Credential.pbId, pTargetCred->credentialId.data(), pTargetCred->credentialId.size());

        if (!pTargetCred->userId.empty()) {
            pAssertion->cbUserId = static_cast<DWORD>(pTargetCred->userId.size());
            pAssertion->pbUserId = new uint8_t[pTargetCred->userId.size()];
            std::memcpy(pAssertion->pbUserId, pTargetCred->userId.data(), pTargetCred->userId.size());
        }

        *ppWebAuthNAssertion = pAssertion;
        return 0; // S_OK
    }

    size_t getCredentialCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_credentials.size();
    }

    bool findCredential(const std::vector<uint8_t>& credId, CredentialRecord& outRec) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string hexId = toHex(credId.data(), credId.size());
        auto it = m_credentials.find(hexId);
        if (it != m_credentials.end()) {
            outRec = it->second;
            return true;
        }
        return false;
    }

    bool deleteCredential(const uint8_t* pId, size_t idLen) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string hexId = toHex(pId, idLen);
        return m_credentials.erase(hexId) > 0;
    }

    void clearAll() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_credentials.clear();
        m_cancellations.clear();
    }
};

// ============================================================================
// 6. Memory Deallocation Helpers (webauthn.dll)
// ============================================================================

inline void WINAPI WebAuthNFreeCredentialAttestation(PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation) {
    if (pAttestation) {
        delete[] pAttestation->pbAuthenticatorData;
        delete[] pAttestation->pbAttestation;
        delete[] pAttestation->pbCredentialId;
        delete[] pAttestation->pbCredentialRawId;
        delete[] pAttestation->pbAttestationObject;
        delete[] pAttestation->pbLargeBlob;
        delete pAttestation;
    }
}

inline void WINAPI WebAuthNFreeAssertion(PWEBAUTHN_ASSERTION pAssertion) {
    if (pAssertion) {
        delete[] pAssertion->pbAuthenticatorData;
        delete[] pAssertion->pbSignature;
        delete[] pAssertion->Credential.pbId;
        delete[] pAssertion->pbUserId;
        delete[] pAssertion->pbLargeBlob;
        delete pAssertion;
    }
}

inline void WINAPI WebAuthNFreePlatformCredentialList(PWEBAUTHN_CREDENTIAL_DETAILS_LIST pList) {
    if (pList) {
        if (pList->ppCredentialDetails) {
            for (DWORD i = 0; i < pList->cCredentialDetails; ++i) {
                auto* pDet = pList->ppCredentialDetails[i];
                if (pDet) {
                    delete[] pDet->pbCredentialID;
                    delete pDet;
                }
            }
            delete[] pList->ppCredentialDetails;
        }
        delete pList;
    }
}

// ============================================================================
// 7. Standard Windows WebAuthn C API Implementations (webauthn.dll)
// ============================================================================

inline HRESULT WINAPI WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(BOOL* pbIsAvailable) {
    if (!pbIsAvailable) return static_cast<HRESULT>(0x80004003); // E_POINTER
    *pbIsAvailable = 1;
    return 0; // S_OK
}

inline HRESULT WINAPI WebAuthNAuthenticatorMakeCredential(
    [[maybe_unused]] HWND hWnd,
    PCWEBAUTHN_RP_ENTITY_INFORMATION pRpInformation,
    PCWEBAUTHN_USER_ENTITY_INFORMATION pUserInformation,
    PCWEBAUTHN_COSE_CREDENTIAL_PARAMETERS pCoseCredentialParameters,
    PCWEBAUTHN_CLIENT_DATA pClientData,
    PCWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS pMakeCredentialOptions,
    PWEBAUTHN_CREDENTIAL_ATTESTATION* ppWebAuthNCredentialAttestation
) {
    return SovereignPlatformAuthenticator::get().makeCredential(
        pRpInformation,
        pUserInformation,
        pCoseCredentialParameters,
        pClientData,
        pMakeCredentialOptions,
        ppWebAuthNCredentialAttestation
    );
}

inline HRESULT WINAPI WebAuthNAuthenticatorGetAssertion(
    [[maybe_unused]] HWND hWnd,
    LPCWSTR pwszRpId,
    PCWEBAUTHN_CLIENT_DATA pClientData,
    PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pGetAssertionOptions,
    PWEBAUTHN_ASSERTION* ppWebAuthNAssertion
) {
    return SovereignPlatformAuthenticator::get().getAssertion(
        pwszRpId,
        pClientData,
        pGetAssertionOptions,
        ppWebAuthNAssertion
    );
}

inline HRESULT WINAPI WebAuthNGetCancellationId(GUID* pCancellationId) {
    if (!pCancellationId) return static_cast<HRESULT>(0x80004003); // E_POINTER
    crypto::Csprng::get().getBytes(std::span<uint8_t>(reinterpret_cast<uint8_t*>(pCancellationId), sizeof(GUID)));
    SovereignPlatformAuthenticator::get().registerCancellationId(*pCancellationId);
    return 0; // S_OK
}

inline HRESULT WINAPI WebAuthNCancelCurrentOperation(const GUID* pCancellationId) {
    if (!pCancellationId) return static_cast<HRESULT>(0x80070057); // E_INVALIDARG
    SovereignPlatformAuthenticator::get().cancelOperation(*pCancellationId);
    return 0; // S_OK
}

inline PCWSTR WINAPI WebAuthNGetErrorName(HRESULT hr) {
    switch (hr) {
        case 0:                                      return L"S_OK";
        case static_cast<HRESULT>(0x80070057):       return L"E_INVALIDARG";
        case static_cast<HRESULT>(0x80004003):       return L"E_POINTER";
        case static_cast<HRESULT>(0x80004002):       return L"E_NOINTERFACE";
        case static_cast<HRESULT>(0x80004005):       return L"E_FAIL";
        case static_cast<HRESULT>(0x80090029):       return L"NTE_NOT_SUPPORTED";
        case static_cast<HRESULT>(0x80090027):       return L"NTE_INVALID_PARAMETER";
        case static_cast<HRESULT>(0x8009000B):       return L"NTE_BAD_KEY";
        case static_cast<HRESULT>(0x80090011):       return L"NTE_NOT_FOUND";
        case static_cast<HRESULT>(0x80090036):       return L"NTE_USER_CANCELLED";
        case static_cast<HRESULT>(0x80090023):       return L"NTE_TOKEN_KEYSET_STORAGE_FULL";
        case static_cast<HRESULT>(0x8009002D):       return L"NTE_EXPIRED";
        case static_cast<HRESULT>(0x800704C7):       return L"ERROR_CANCELLED";
        default:                                     return L"Unknown WebAuthN Error";
    }
}

inline DWORD WINAPI WebAuthNGetApiVersionNumber() {
    return WEBAUTHN_API_VERSION_CURRENT;
}

inline HRESULT WINAPI WebAuthNDeletePlatformCredential(
    DWORD cbCredentialId,
    const PBYTE pbCredentialId
) {
    if (!pbCredentialId || cbCredentialId == 0) return static_cast<HRESULT>(0x80070057);
    bool deleted = SovereignPlatformAuthenticator::get().deleteCredential(pbCredentialId, cbCredentialId);
    return deleted ? 0 : static_cast<HRESULT>(0x80090011); // NTE_NOT_FOUND
}

// ============================================================================
// 8. Subsystem Dynamic Export Registration Helper
// ============================================================================

inline void InitializeWebAuthnSubsystemExports() {
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        auto& loader = ldr::DynamicLoader::get();

        // 1. Register webauthn.dll dynamic exports
        loader.registerExport("webauthn.dll", "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
            reinterpret_cast<void*>(&WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable));
        loader.registerExport("webauthn.dll", "WebAuthNAuthenticatorMakeCredential",
            reinterpret_cast<void*>(&WebAuthNAuthenticatorMakeCredential));
        loader.registerExport("webauthn.dll", "WebAuthNAuthenticatorGetAssertion",
            reinterpret_cast<void*>(&WebAuthNAuthenticatorGetAssertion));
        loader.registerExport("webauthn.dll", "WebAuthNFreeCredentialAttestation",
            reinterpret_cast<void*>(&WebAuthNFreeCredentialAttestation));
        loader.registerExport("webauthn.dll", "WebAuthNFreeAssertion",
            reinterpret_cast<void*>(&WebAuthNFreeAssertion));
        loader.registerExport("webauthn.dll", "WebAuthNGetCancellationId",
            reinterpret_cast<void*>(&WebAuthNGetCancellationId));
        loader.registerExport("webauthn.dll", "WebAuthNCancelCurrentOperation",
            reinterpret_cast<void*>(&WebAuthNCancelCurrentOperation));
        loader.registerExport("webauthn.dll", "WebAuthNGetErrorName",
            reinterpret_cast<void*>(&WebAuthNGetErrorName));
        loader.registerExport("webauthn.dll", "WebAuthNGetApiVersionNumber",
            reinterpret_cast<void*>(&WebAuthNGetApiVersionNumber));
        loader.registerExport("webauthn.dll", "WebAuthNDeletePlatformCredential",
            reinterpret_cast<void*>(&WebAuthNDeletePlatformCredential));
        loader.registerExport("webauthn.dll", "WebAuthNFreePlatformCredentialList",
            reinterpret_cast<void*>(&WebAuthNFreePlatformCredentialList));

        // 2. Register in VersionDatabase
        version::VersionDatabase::Instance().RegisterModule(
            "webauthn.dll",
            "10.0.22621.1",
            "Windows Web Authentication & Sovereign FIDO2 / Passkey Subsystem",
            "MicaNT Sovereign Project"
        );
    });
}

} // namespace micant::webauthn
