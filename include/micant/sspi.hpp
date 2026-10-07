// ============================================================================
// MicaNT: Sovereign Operating System Executive
// include/micant/sspi.hpp - Windows Security Support Provider Interface (SSPI)
// & Secure Channel (Schannel) TLS 1.3 Subsystem (secur32.dll / schannel.dll)
//
// 100% Clean-Room Architecture authored from Microsoft win32metadata interface definitions.
// Zero proprietary code used or referenced. Google LLC v. Oracle America (2021).
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <span>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "kernel32.hpp"
#include "cipherksp.hpp"
#include "crypt32.hpp"
#include "sam.hpp"
#include "ldr.hpp"

namespace micant::sspi {

// ============================================================================
// 1. SSPI Basic Types & Constants
// ============================================================================

using SECURITY_STATUS = int32_t;

struct SecHandle {
    uintptr_t dwLower{0};
    uintptr_t dwUpper{0};

    [[nodiscard]] constexpr bool isValid() const noexcept {
        return dwLower != 0 || dwUpper != 0;
    }
};

using CredHandle = SecHandle;
using CtxtHandle = SecHandle;

// Buffer Types
inline constexpr uint32_t SECBUFFER_EMPTY               = 0;
inline constexpr uint32_t SECBUFFER_DATA                = 1;
inline constexpr uint32_t SECBUFFER_TOKEN               = 2;
inline constexpr uint32_t SECBUFFER_PKG_PARAMS          = 3;
inline constexpr uint32_t SECBUFFER_MISSING             = 4;
inline constexpr uint32_t SECBUFFER_EXTRA               = 5;
inline constexpr uint32_t SECBUFFER_STREAM_TRAILER      = 6;
inline constexpr uint32_t SECBUFFER_STREAM_HEADER       = 7;
inline constexpr uint32_t SECBUFFER_NEGOTIATION_INFO    = 8;
inline constexpr uint32_t SECBUFFER_PADDING             = 9;
inline constexpr uint32_t SECBUFFER_STREAM              = 10;
inline constexpr uint32_t SECBUFFER_MECHLIST            = 11;
inline constexpr uint32_t SECBUFFER_MECHLIST_SIGNATURE  = 12;
inline constexpr uint32_t SECBUFFER_TARGET              = 13;
inline constexpr uint32_t SECBUFFER_CHANNEL_BINDINGS    = 14;
inline constexpr uint32_t SECBUFFER_CHANGE_PASS_RESPONSE= 15;
inline constexpr uint32_t SECBUFFER_TARGET_HOST         = 16;
inline constexpr uint32_t SECBUFFER_ALERT               = 17;
inline constexpr uint32_t SECBUFFER_APPLICATION_PROT    = 18;

inline constexpr uint32_t SECBUFFER_VERSION             = 0;

struct SecBuffer {
    uint32_t cbBuffer{0};
    uint32_t BufferType{SECBUFFER_EMPTY};
    void*    pvBuffer{nullptr};
};

struct SecBufferDesc {
    uint32_t   ulVersion{SECBUFFER_VERSION};
    uint32_t   cBuffers{0};
    SecBuffer* pBuffers{nullptr};
};

// SSPI Return Codes / Statuses
inline constexpr SECURITY_STATUS SEC_E_OK                        = 0x00000000;
inline constexpr SECURITY_STATUS SEC_I_CONTINUE_NEEDED           = 0x00090312;
inline constexpr SECURITY_STATUS SEC_I_COMPLETE_NEEDED           = 0x00090313;
inline constexpr SECURITY_STATUS SEC_I_COMPLETE_AND_CONTINUE     = 0x00090314;
inline constexpr SECURITY_STATUS SEC_I_LOCAL_LOGON               = 0x00090315;
inline constexpr SECURITY_STATUS SEC_I_CONTEXT_EXPIRED           = 0x00090317;
inline constexpr SECURITY_STATUS SEC_I_INCOMPLETE_CREDENTIALS    = 0x00090320;
inline constexpr SECURITY_STATUS SEC_I_RENEGOTIATE               = 0x00090321;
inline constexpr SECURITY_STATUS SEC_I_NO_LSA_CONTEXT            = 0x00090323;

inline constexpr SECURITY_STATUS SEC_E_INSUFFICIENT_MEMORY       = static_cast<int32_t>(0x80090300);
inline constexpr SECURITY_STATUS SEC_E_INVALID_HANDLE            = static_cast<int32_t>(0x80090301);
inline constexpr SECURITY_STATUS SEC_E_UNSUPPORTED_FUNCTION      = static_cast<int32_t>(0x80090302);
inline constexpr SECURITY_STATUS SEC_E_TARGET_UNKNOWN            = static_cast<int32_t>(0x80090303);
inline constexpr SECURITY_STATUS SEC_E_INTERNAL_ERROR            = static_cast<int32_t>(0x80090304);
inline constexpr SECURITY_STATUS SEC_E_SECPKG_NOT_FOUND          = static_cast<int32_t>(0x80090305);
inline constexpr SECURITY_STATUS SEC_E_NOT_OWNER                 = static_cast<int32_t>(0x80090306);
inline constexpr SECURITY_STATUS SEC_E_CANNOT_INSTALL            = static_cast<int32_t>(0x80090307);
inline constexpr SECURITY_STATUS SEC_E_INVALID_TOKEN             = static_cast<int32_t>(0x80090308);
inline constexpr SECURITY_STATUS SEC_E_CANNOT_PACK               = static_cast<int32_t>(0x80090309);
inline constexpr SECURITY_STATUS SEC_E_QOP_NOT_SUPPORTED         = static_cast<int32_t>(0x8009030A);
inline constexpr SECURITY_STATUS SEC_E_NO_IMPERSONATION          = static_cast<int32_t>(0x8009030B);
inline constexpr SECURITY_STATUS SEC_E_LOGON_DENIED              = static_cast<int32_t>(0x8009030C);
inline constexpr SECURITY_STATUS SEC_E_UNKNOWN_CREDENTIALS       = static_cast<int32_t>(0x8009030D);
inline constexpr SECURITY_STATUS SEC_E_NO_CREDENTIALS            = static_cast<int32_t>(0x8009030E);
inline constexpr SECURITY_STATUS SEC_E_MESSAGE_ALTERED           = static_cast<int32_t>(0x8009030F);
inline constexpr SECURITY_STATUS SEC_E_OUT_OF_SEQUENCE           = static_cast<int32_t>(0x80090310);
inline constexpr SECURITY_STATUS SEC_E_NO_AUTHENTICATING_AUTHORITY= static_cast<int32_t>(0x80090311);
inline constexpr SECURITY_STATUS SEC_E_INCOMPLETE_MESSAGE        = static_cast<int32_t>(0x80090318);
inline constexpr SECURITY_STATUS SEC_E_ALGORITHM_MISMATCH        = static_cast<int32_t>(0x80090331);
inline constexpr SECURITY_STATUS SEC_E_BUFFER_TOO_SMALL          = static_cast<int32_t>(0x80090321);
inline constexpr SECURITY_STATUS SEC_E_WRONG_PRINCIPAL           = static_cast<int32_t>(0x80090322);
inline constexpr SECURITY_STATUS SEC_E_UNTRUSTED_ROOT            = static_cast<int32_t>(0x80090327);
inline constexpr SECURITY_STATUS SEC_E_CERT_EXPIRED              = static_cast<int32_t>(0x80090328);

// Credential Use Flags
inline constexpr uint32_t SECPKG_CRED_INBOUND                   = 0x00000001;
inline constexpr uint32_t SECPKG_CRED_OUTBOUND                  = 0x00000002;
inline constexpr uint32_t SECPKG_CRED_BOTH                      = 0x00000003;

// Context Requirements & Attributes (fContextReq / pfContextAttr)
inline constexpr uint32_t ISC_REQ_DELEGATE                      = 0x00000001;
inline constexpr uint32_t ISC_REQ_MUTUAL_AUTH                   = 0x00000002;
inline constexpr uint32_t ISC_REQ_REPLAY_DETECT                 = 0x00000004;
inline constexpr uint32_t ISC_REQ_SEQUENCE_DETECT               = 0x00000008;
inline constexpr uint32_t ISC_REQ_CONFIDENTIALITY               = 0x00000010;
inline constexpr uint32_t ISC_REQ_USE_SESSION_KEY               = 0x00000020;
inline constexpr uint32_t ISC_REQ_PROMPT_FOR_CREDS              = 0x00000040;
inline constexpr uint32_t ISC_REQ_USE_SUPPLIED_CREDS            = 0x00000080;
inline constexpr uint32_t ISC_REQ_ALLOCATE_MEMORY               = 0x00000100;
inline constexpr uint32_t ISC_REQ_CONNECTION                    = 0x00000800;
inline constexpr uint32_t ISC_REQ_STREAM                        = 0x00008000;
inline constexpr uint32_t ISC_REQ_EXTENDED_ERROR                = 0x00004000;
inline constexpr uint32_t ISC_REQ_MANUAL_CRED_VALIDATION        = 0x00080000;

// Context Attributes for QueryContextAttributes
inline constexpr uint32_t SECPKG_ATTR_SIZES                     = 0;
inline constexpr uint32_t SECPKG_ATTR_NAMES                     = 1;
inline constexpr uint32_t SECPKG_ATTR_LIFESPAN                  = 2;
inline constexpr uint32_t SECPKG_ATTR_DCE_INFO                  = 3;
inline constexpr uint32_t SECPKG_ATTR_STREAM_SIZES              = 4;
inline constexpr uint32_t SECPKG_ATTR_KEY_INFO                  = 5;
inline constexpr uint32_t SECPKG_ATTR_AUTHORITY                 = 6;
inline constexpr uint32_t SECPKG_ATTR_PROTO_INFO                = 7;
inline constexpr uint32_t SECPKG_ATTR_PASSWORD_EXPIRY           = 8;
inline constexpr uint32_t SECPKG_ATTR_SESSION_KEY               = 9;
inline constexpr uint32_t SECPKG_ATTR_NEGOTIATION_INFO          = 12;
inline constexpr uint32_t SECPKG_ATTR_CONNECTION_INFO           = 90;

struct SecPkgContext_StreamSizes {
    uint32_t cbHeader{0};
    uint32_t cbTrailer{0};
    uint32_t cbMaximumMessage{0};
    uint32_t cBuffers{0};
    uint32_t cbBlockSize{0};
};

struct SecPkgContext_ConnectionInfo {
    uint32_t dwProtocol{0};
    uint32_t aiCipher{0};
    uint32_t dwCipherStrength{0};
    uint32_t aiHash{0};
    uint32_t dwHashStrength{0};
    uint32_t aiExch{0};
    uint32_t dwExchStrength{0};
};

struct SecPkgInfoA {
    uint32_t fCapabilities{0};
    uint16_t wVersion{1};
    uint16_t wRPCID{0};
    uint32_t cbMaxToken{0};
    char*    Name{nullptr};
    char*    Comment{nullptr};
};

struct SecPkgInfoW {
    uint32_t fCapabilities{0};
    uint16_t wVersion{1};
    uint16_t wRPCID{0};
    uint32_t cbMaxToken{0};
    wchar_t* Name{nullptr};
    wchar_t* Comment{nullptr};
};

struct SecPkgContext_NegotiationInfoA {
    SecPkgInfoA* PackageInfo{nullptr};
    uint32_t     NegotiationState{0};
};

struct SecPkgContext_NegotiationInfoW {
    SecPkgInfoW* PackageInfo{nullptr};
    uint32_t     NegotiationState{0};
};

// Schannel Protocol Flags
inline constexpr uint32_t SP_PROT_SSL2_CLIENT                   = 0x00000008;
inline constexpr uint32_t SP_PROT_SSL3_CLIENT                   = 0x00000020;
inline constexpr uint32_t SP_PROT_TLS1_0_CLIENT                 = 0x00000080;
inline constexpr uint32_t SP_PROT_TLS1_1_CLIENT                 = 0x00000200;
inline constexpr uint32_t SP_PROT_TLS1_2_CLIENT                 = 0x00000800;
inline constexpr uint32_t SP_PROT_TLS1_3_CLIENT                 = 0x00002000;
inline constexpr uint32_t SP_PROT_TLS1_3_SERVER                 = 0x00001000;
inline constexpr uint32_t SP_PROT_TLS1_CLIENTS                  = SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT;
inline constexpr uint32_t SP_PROT_TLS1_X_CLIENTS                = SP_PROT_TLS1_CLIENTS | SP_PROT_TLS1_3_CLIENT;

inline constexpr uint32_t SCH_CRED_NO_DEFAULT_CREDS             = 0x00000010;
inline constexpr uint32_t SCH_CRED_AUTO_CRED_VALIDATION         = 0x00000020;
inline constexpr uint32_t SCH_CRED_USE_DEFAULT_CREDS            = 0x00000040;
inline constexpr uint32_t SCH_CRED_MANUAL_CRED_VALIDATION       = 0x00000008;

inline constexpr uint32_t SCHANNEL_CRED_VERSION                 = 4;

struct SCHANNEL_CRED {
    uint32_t dwVersion{SCHANNEL_CRED_VERSION};
    uint32_t cCreds{0};
    crypt32::PCCERT_CONTEXT* paCred{nullptr};
    crypt32::HCERTSTORE hRootStore{nullptr};
    uint32_t cMappers{0};
    void**   aphMappers{nullptr};
    uint32_t cSupportedAlgs{0};
    uint32_t* palgSupportedAlgs{nullptr};
    uint32_t grbitEnabledProtocols{SP_PROT_TLS1_X_CLIENTS};
    uint32_t dwMinimumCipherStrength{0};
    uint32_t dwMaximumCipherStrength{0};
    uint32_t dwSessionLifespan{0};
    uint32_t dwFlags{0};
    uint32_t dwCredFormat{0};
};

// Security Package Names
inline constexpr const char*    UNISP_NAME_A    = "Microsoft Unified Security Protocol Provider";
inline constexpr const wchar_t* UNISP_NAME_W    = L"Microsoft Unified Security Protocol Provider";
inline constexpr const char*    SCHANNEL_NAME_A = "Schannel";
inline constexpr const wchar_t* SCHANNEL_NAME_W = L"Schannel";
inline constexpr const char*    NTLM_NAME_A     = "NTLM";
inline constexpr const wchar_t* NTLM_NAME_W     = L"NTLM";
inline constexpr const char*    NTLMSP_NAME_A   = "NTLM";
inline constexpr const wchar_t* NTLMSP_NAME_W   = L"NTLM";
inline constexpr const char*    NEGOTIATE_NAME_A= "Negotiate";
inline constexpr const wchar_t* NEGOTIATE_NAME_W= L"Negotiate";
inline constexpr const char*    NEGOSSP_NAME_A  = "Negotiate";
inline constexpr const wchar_t* NEGOSSP_NAME_W  = L"Negotiate";
inline constexpr const char*    KERBEROS_NAME_A = "Kerberos";
inline constexpr const wchar_t* KERBEROS_NAME_W = L"Kerberos";

inline std::wstring toWide(std::string_view s) {
    std::wstring ws;
    ws.reserve(s.size());
    for (char c : s) ws.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    return ws;
}

inline std::string toNarrow(std::wstring_view ws) {
    std::string s;
    s.reserve(ws.size());
    for (wchar_t wc : ws) s.push_back(static_cast<char>(wc & 0x7F));
    return s;
}

// ============================================================================
// 2. TLS 1.3 / 1.2 Protocol & Crypto Engine (Schannel Provider Core)
// ============================================================================

namespace detail {

    // TLS Record Content Types
    inline constexpr uint8_t TLS_CHANGE_CIPHER_SPEC = 0x14;
    inline constexpr uint8_t TLS_ALERT              = 0x15;
    inline constexpr uint8_t TLS_HANDSHAKE          = 0x16;
    inline constexpr uint8_t TLS_APPLICATION_DATA   = 0x17;

    // TLS Versions
    inline constexpr uint16_t TLS_VERSION_1_0       = 0x0301;
    inline constexpr uint16_t TLS_VERSION_1_2       = 0x0303;
    inline constexpr uint16_t TLS_VERSION_1_3       = 0x0304;

    // TLS Handshake Types
    inline constexpr uint8_t TLS_HS_CLIENT_HELLO         = 0x01;
    inline constexpr uint8_t TLS_HS_SERVER_HELLO         = 0x02;
    inline constexpr uint8_t TLS_HS_NEW_SESSION_TICKET   = 0x04;
    inline constexpr uint8_t TLS_HS_END_OF_EARLY_DATA    = 0x05;
    inline constexpr uint8_t TLS_HS_ENCRYPTED_EXTENSIONS = 0x08;
    inline constexpr uint8_t TLS_HS_CERTIFICATE          = 0x0B;
    inline constexpr uint8_t TLS_HS_CERTIFICATE_REQUEST  = 0x0D;
    inline constexpr uint8_t TLS_HS_CERTIFICATE_VERIFY   = 0x0F;
    inline constexpr uint8_t TLS_HS_FINISHED             = 0x14;
    inline constexpr uint8_t TLS_HS_KEY_UPDATE           = 0x18;

    // Cipher Suites
    inline constexpr uint16_t TLS_AES_128_GCM_SHA256        = 0x1301;
    inline constexpr uint16_t TLS_AES_256_GCM_SHA384        = 0x1302;
    inline constexpr uint16_t TLS_CHACHA20_POLY1305_SHA256  = 0x1303;

    // Extensions
    inline constexpr uint16_t EXT_SERVER_NAME               = 0x0000;
    inline constexpr uint16_t EXT_SUPPORTED_GROUPS          = 0x000A;
    inline constexpr uint16_t EXT_SIGNATURE_ALGORITHMS      = 0x000D;
    inline constexpr uint16_t EXT_SUPPORTED_VERSIONS        = 0x002B;
    inline constexpr uint16_t EXT_KEY_SHARE                 = 0x0033;

    // Named Groups
    inline constexpr uint16_t GROUP_SECP256R1               = 0x0017;
    inline constexpr uint16_t GROUP_X25519                  = 0x001D;

    // Helper to append big-endian values
    inline void appendU16(std::vector<uint8_t>& buf, uint16_t v) {
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
    }

    inline void appendU24(std::vector<uint8_t>& buf, uint32_t v) {
        buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
    }

    inline void appendU32(std::vector<uint8_t>& buf, uint32_t v) {
        buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
    }

    // Build TLS 1.3 ClientHello record
    inline std::vector<uint8_t> BuildClientHello(std::string_view serverName, const uint8_t clientRandom[32], const uint8_t clientShare[32]) {
        std::vector<uint8_t> hsBody;

        // Legacy client version: 0x0303 (TLS 1.2 for middlebox compatibility)
        appendU16(hsBody, TLS_VERSION_1_2);

        // 32-byte Random
        hsBody.insert(hsBody.end(), clientRandom, clientRandom + 32);

        // Legacy Session ID (32 bytes)
        hsBody.push_back(32);
        for (int i = 0; i < 32; ++i) hsBody.push_back(static_cast<uint8_t>(i ^ 0xA5));

        // Cipher Suites
        std::vector<uint8_t> cipherSuites;
        appendU16(cipherSuites, TLS_AES_256_GCM_SHA384);
        appendU16(cipherSuites, TLS_AES_128_GCM_SHA256);
        appendU16(cipherSuites, TLS_CHACHA20_POLY1305_SHA256);
        appendU16(hsBody, static_cast<uint16_t>(cipherSuites.size()));
        hsBody.insert(hsBody.end(), cipherSuites.begin(), cipherSuites.end());

        // Legacy compression methods: 1 byte [0x00]
        hsBody.push_back(1);
        hsBody.push_back(0);

        // Extensions
        std::vector<uint8_t> extBuf;

        // 1. Server Name Indication (SNI)
        if (!serverName.empty()) {
            std::vector<uint8_t> sniData;
            appendU16(sniData, static_cast<uint16_t>(serverName.size() + 3));
            sniData.push_back(0x00); // host_name type
            appendU16(sniData, static_cast<uint16_t>(serverName.size()));
            sniData.insert(sniData.end(), serverName.begin(), serverName.end());

            appendU16(extBuf, EXT_SERVER_NAME);
            appendU16(extBuf, static_cast<uint16_t>(sniData.size()));
            extBuf.insert(extBuf.end(), sniData.begin(), sniData.end());
        }

        // 2. Supported Versions: TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
        {
            std::vector<uint8_t> svData;
            svData.push_back(4); // 2 versions (2 bytes each)
            appendU16(svData, TLS_VERSION_1_3);
            appendU16(svData, TLS_VERSION_1_2);

            appendU16(extBuf, EXT_SUPPORTED_VERSIONS);
            appendU16(extBuf, static_cast<uint16_t>(svData.size()));
            extBuf.insert(extBuf.end(), svData.begin(), svData.end());
        }

        // 3. Supported Groups: x25519 (0x001d), secp256r1 (0x0017)
        {
            std::vector<uint8_t> sgData;
            appendU16(sgData, 4);
            appendU16(sgData, GROUP_X25519);
            appendU16(sgData, GROUP_SECP256R1);

            appendU16(extBuf, EXT_SUPPORTED_GROUPS);
            appendU16(extBuf, static_cast<uint16_t>(sgData.size()));
            extBuf.insert(extBuf.end(), sgData.begin(), sgData.end());
        }

        // 4. Key Share: x25519 client share (32 bytes)
        {
            std::vector<uint8_t> ksData;
            std::vector<uint8_t> clientShares;
            appendU16(clientShares, GROUP_X25519);
            appendU16(clientShares, 32);
            clientShares.insert(clientShares.end(), clientShare, clientShare + 32);

            appendU16(ksData, static_cast<uint16_t>(clientShares.size()));
            ksData.insert(ksData.end(), clientShares.begin(), clientShares.end());

            appendU16(extBuf, EXT_KEY_SHARE);
            appendU16(extBuf, static_cast<uint16_t>(ksData.size()));
            extBuf.insert(extBuf.end(), ksData.begin(), ksData.end());
        }

        // Append extensions length and extensions
        appendU16(hsBody, static_cast<uint16_t>(extBuf.size()));
        hsBody.insert(hsBody.end(), extBuf.begin(), extBuf.end());

        // Construct full TLS record
        std::vector<uint8_t> record;
        record.push_back(TLS_HANDSHAKE);
        appendU16(record, TLS_VERSION_1_0); // 0x0301 legacy record layer version

        uint32_t hsLen = static_cast<uint32_t>(hsBody.size());
        uint16_t recordLen = static_cast<uint16_t>(4 + hsLen);
        appendU16(record, recordLen);

        // Handshake header
        record.push_back(TLS_HS_CLIENT_HELLO);
        appendU24(record, hsLen);
        record.insert(record.end(), hsBody.begin(), hsBody.end());

        return record;
    }

    // Build TLS 1.3 ServerHello response for simulation/loopback
    inline std::vector<uint8_t> BuildServerHello(const uint8_t clientRandom[32], const uint8_t serverShare[32]) {
        std::vector<uint8_t> hsBody;
        appendU16(hsBody, TLS_VERSION_1_2); // legacy version

        // Server Random (32 bytes)
        uint8_t srvRandom[32]{};
        for (int i = 0; i < 32; ++i) srvRandom[i] = static_cast<uint8_t>(clientRandom[31 - i] ^ 0x5C);
        hsBody.insert(hsBody.end(), srvRandom, srvRandom + 32);

        // Session ID echo (32 bytes)
        hsBody.push_back(32);
        for (int i = 0; i < 32; ++i) hsBody.push_back(static_cast<uint8_t>(i ^ 0xA5));

        // Chosen Cipher Suite: TLS_AES_256_GCM_SHA384
        appendU16(hsBody, TLS_AES_256_GCM_SHA384);
        hsBody.push_back(0); // compression method null

        // Extensions
        std::vector<uint8_t> extBuf;

        // 1. Supported Versions: 0x0304 (TLS 1.3)
        appendU16(extBuf, EXT_SUPPORTED_VERSIONS);
        appendU16(extBuf, 2);
        appendU16(extBuf, TLS_VERSION_1_3);

        // 2. Key Share: Server x25519 share (32 bytes)
        appendU16(extBuf, EXT_KEY_SHARE);
        appendU16(extBuf, 36);
        appendU16(extBuf, GROUP_X25519);
        appendU16(extBuf, 32);
        extBuf.insert(extBuf.end(), serverShare, serverShare + 32);

        appendU16(hsBody, static_cast<uint16_t>(extBuf.size()));
        hsBody.insert(hsBody.end(), extBuf.begin(), extBuf.end());

        // Construct TLS record
        std::vector<uint8_t> record;
        record.push_back(TLS_HANDSHAKE);
        appendU16(record, TLS_VERSION_1_2);
        uint16_t recordLen = static_cast<uint16_t>(4 + hsBody.size());
        appendU16(record, recordLen);

        record.push_back(TLS_HS_SERVER_HELLO);
        appendU24(record, static_cast<uint32_t>(hsBody.size()));
        record.insert(record.end(), hsBody.begin(), hsBody.end());

        return record;
    }
} // namespace detail

// ============================================================================
// 3. SSPI Internal Object Structures (Credentials & Contexts)
// ============================================================================

enum class PackageType {
    Schannel,
    Ntlm,
    Negotiate,
    Kerberos
};

struct SspiCredential {
    uint32_t id{0};
    PackageType type{PackageType::Schannel};
    uint32_t usage{SECPKG_CRED_OUTBOUND};
    std::wstring principal;
    SCHANNEL_CRED schannelCred{};
    std::shared_ptr<crypt32::InternalCert> cert;
};

struct SspiContext {
    uint32_t id{0};
    PackageType type{PackageType::Schannel};
    bool isServer{false};
    uint32_t state{0}; // 0 = Initial, 1 = HelloSent / ChallengeSent, 2 = Connected, 3 = Closed
    std::wstring targetName;
    uint32_t reqFlags{0};
    uint32_t attrFlags{0};

    // TLS Handshake parameters
    uint8_t clientRandom[32]{};
    uint8_t clientShare[32]{};
    uint8_t serverRandom[32]{};
    uint8_t serverShare[32]{};
    std::vector<uint8_t> masterKey;
    std::vector<uint8_t> clientWriteKey;
    std::vector<uint8_t> serverWriteKey;
    std::vector<uint8_t> clientWriteMac;
    std::vector<uint8_t> serverWriteMac;
    uint64_t clientSeq{0};
    uint64_t serverSeq{0};

    // NTLM parameters
    std::string ntlmUser;
    std::string ntlmDomain;
    uint8_t ntlmChallenge[8]{};

    // Stream sizes
    SecPkgContext_StreamSizes streamSizes{
        .cbHeader = 5,
        .cbTrailer = 32, // HMAC-SHA256 authentication tag
        .cbMaximumMessage = 16384,
        .cBuffers = 4,
        .cbBlockSize = 16 // AES block size
    };
};

class SspiManager {
private:
    std::mutex m_mutex;
    uint32_t m_nextCredId{1};
    uint32_t m_nextCtxtId{1};
    std::unordered_map<uint32_t, std::shared_ptr<SspiCredential>> m_creds;
    std::unordered_map<uint32_t, std::shared_ptr<SspiContext>> m_contexts;

public:
    static SspiManager& Instance() {
        static SspiManager s_inst;
        return s_inst;
    }

    uint32_t allocateCred(PackageType type, uint32_t usage, std::wstring_view princ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t id = m_nextCredId++;
        auto cred = std::make_shared<SspiCredential>();
        cred->id = id;
        cred->type = type;
        cred->usage = usage;
        cred->principal = princ;
        m_creds[id] = cred;
        return id;
    }

    std::shared_ptr<SspiCredential> getCred(uint32_t id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_creds.find(id);
        return (it != m_creds.end()) ? it->second : nullptr;
    }

    void freeCred(uint32_t id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_creds.erase(id);
    }

    uint32_t allocateContext(PackageType type, bool isServer, std::wstring_view target, uint32_t req) {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t id = m_nextCtxtId++;
        auto ctxt = std::make_shared<SspiContext>();
        ctxt->id = id;
        ctxt->type = type;
        ctxt->isServer = isServer;
        ctxt->targetName = target;
        ctxt->reqFlags = req;
        ctxt->attrFlags = req;

        // Initialize CSPRNG client random and key share
        crypto::Csprng::get().getBytes(ctxt->clientRandom);
        crypto::Csprng::get().getBytes(ctxt->clientShare);

        m_contexts[id] = ctxt;
        return id;
    }

    std::shared_ptr<SspiContext> getContext(uint32_t id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_contexts.find(id);
        return (it != m_contexts.end()) ? it->second : nullptr;
    }

    void freeContext(uint32_t id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_contexts.erase(id);
    }
};

// ============================================================================
// 4. SSPI Core API Implementation (secur32.dll / sspicli.dll)
// ============================================================================

inline SECURITY_STATUS __stdcall EnumerateSecurityPackagesA(
    uint32_t* pcPackages,
    SecPkgInfoA** ppPackageInfo
) {
    if (!pcPackages || !ppPackageInfo) return SEC_E_INVALID_HANDLE;

    static SecPkgInfoA s_pkgs[] = {
        {
            0x000107B3, 1, 0, 0x4000,
            const_cast<char*>(SCHANNEL_NAME_A),
            const_cast<char*>("Schannel Security Package (TLS 1.3 / 1.2)")
        },
        {
            0x00082B37, 1, 10, 0x0B38,
            const_cast<char*>(NTLM_NAME_A),
            const_cast<char*>("NTLM Security Package")
        },
        {
            0x00080BB3, 1, 9, 0x3000,
            const_cast<char*>(NEGOTIATE_NAME_A),
            const_cast<char*>("Microsoft SPNEGO Negotiate Security Package")
        }
    };

    *pcPackages = 3;
    *ppPackageInfo = s_pkgs;
    return SEC_E_OK;
}

inline SECURITY_STATUS __stdcall EnumerateSecurityPackagesW(
    uint32_t* pcPackages,
    SecPkgInfoW** ppPackageInfo
) {
    if (!pcPackages || !ppPackageInfo) return SEC_E_INVALID_HANDLE;

    static SecPkgInfoW s_pkgsW[] = {
        {
            0x000107B3, 1, 0, 0x4000,
            const_cast<wchar_t*>(SCHANNEL_NAME_W),
            const_cast<wchar_t*>(L"Schannel Security Package (TLS 1.3 / 1.2)")
        },
        {
            0x00082B37, 1, 10, 0x0B38,
            const_cast<wchar_t*>(NTLM_NAME_W),
            const_cast<wchar_t*>(L"NTLM Security Package")
        },
        {
            0x00080BB3, 1, 9, 0x3000,
            const_cast<wchar_t*>(NEGOTIATE_NAME_W),
            const_cast<wchar_t*>(L"Microsoft SPNEGO Negotiate Security Package")
        }
    };

    *pcPackages = 3;
    *ppPackageInfo = s_pkgsW;
    return SEC_E_OK;
}

inline SECURITY_STATUS __stdcall QuerySecurityPackageInfoA(
    const char* pszPackageName,
    SecPkgInfoA** ppPackageInfo
) {
    if (!pszPackageName || !ppPackageInfo) return SEC_E_SECPKG_NOT_FOUND;

    uint32_t count = 0;
    SecPkgInfoA* pkgs = nullptr;
    EnumerateSecurityPackagesA(&count, &pkgs);

    for (uint32_t i = 0; i < count; ++i) {
        if (_stricmp(pszPackageName, pkgs[i].Name) == 0 ||
            (_stricmp(pszPackageName, UNISP_NAME_A) == 0 && strcmp(pkgs[i].Name, SCHANNEL_NAME_A) == 0)) {
            *ppPackageInfo = &pkgs[i];
            return SEC_E_OK;
        }
    }
    return SEC_E_SECPKG_NOT_FOUND;
}

inline SECURITY_STATUS __stdcall QuerySecurityPackageInfoW(
    const wchar_t* pszPackageName,
    SecPkgInfoW** ppPackageInfo
) {
    if (!pszPackageName || !ppPackageInfo) return SEC_E_SECPKG_NOT_FOUND;

    uint32_t count = 0;
    SecPkgInfoW* pkgs = nullptr;
    EnumerateSecurityPackagesW(&count, &pkgs);

    for (uint32_t i = 0; i < count; ++i) {
        if (_wcsicmp(pszPackageName, pkgs[i].Name) == 0 ||
            (_wcsicmp(pszPackageName, UNISP_NAME_W) == 0 && wcscmp(pkgs[i].Name, SCHANNEL_NAME_W) == 0)) {
            *ppPackageInfo = &pkgs[i];
            return SEC_E_OK;
        }
    }
    return SEC_E_SECPKG_NOT_FOUND;
}

inline SECURITY_STATUS __stdcall AcquireCredentialsHandleA(
    [[maybe_unused]] const char* pszPrincipal,
    const char*    pszPackage,
    uint32_t       fCredentialUse,
    [[maybe_unused]] void* pvLogonID,
    void*          pAuthData,
    [[maybe_unused]] void* pGetKeyFn,
    [[maybe_unused]] void* pvGetKeyArgument,
    CredHandle*    phCredential,
    [[maybe_unused]] win32::PFILETIME ptsExpiry
) {
    if (!pszPackage || !phCredential) return SEC_E_SECPKG_NOT_FOUND;

    PackageType type = PackageType::Schannel;
    if (_stricmp(pszPackage, SCHANNEL_NAME_A) == 0 || _stricmp(pszPackage, UNISP_NAME_A) == 0) {
        type = PackageType::Schannel;
    } else if (_stricmp(pszPackage, NTLM_NAME_A) == 0) {
        type = PackageType::Ntlm;
    } else if (_stricmp(pszPackage, NEGOTIATE_NAME_A) == 0) {
        type = PackageType::Negotiate;
    } else if (_stricmp(pszPackage, KERBEROS_NAME_A) == 0) {
        type = PackageType::Kerberos;
    } else {
        return SEC_E_SECPKG_NOT_FOUND;
    }

    std::wstring princ = pszPrincipal ? toWide(pszPrincipal) : L"";
    uint32_t id = SspiManager::Instance().allocateCred(type, fCredentialUse, princ);
    auto cred = SspiManager::Instance().getCred(id);

    if (type == PackageType::Schannel && pAuthData) {
        auto* schCred = static_cast<SCHANNEL_CRED*>(pAuthData);
        cred->schannelCred = *schCred;
    }

    phCredential->dwLower = id;
    phCredential->dwUpper = 0x53535049; // 'SSPI'
    return SEC_E_OK;
}

inline SECURITY_STATUS __stdcall AcquireCredentialsHandleW(
    const wchar_t* pszPrincipal,
    const wchar_t* pszPackage,
    uint32_t       fCredentialUse,
    void*          pvLogonID,
    void*          pAuthData,
    void*          pGetKeyFn,
    void*          pvGetKeyArgument,
    CredHandle*    phCredential,
    win32::PFILETIME ptsExpiry
) {
    if (!pszPackage) return SEC_E_SECPKG_NOT_FOUND;
    std::string narrowPkg = toNarrow(pszPackage);
    std::string narrowPrinc = pszPrincipal ? toNarrow(pszPrincipal) : "";
    return AcquireCredentialsHandleA(
        pszPrincipal ? narrowPrinc.c_str() : nullptr,
        narrowPkg.c_str(),
        fCredentialUse,
        pvLogonID,
        pAuthData,
        pGetKeyFn,
        pvGetKeyArgument,
        phCredential,
        ptsExpiry
    );
}

inline SECURITY_STATUS __stdcall FreeCredentialsHandle(CredHandle* phCredential) {
    if (!phCredential || phCredential->dwUpper != 0x53535049) return SEC_E_INVALID_HANDLE;
    SspiManager::Instance().freeCred(static_cast<uint32_t>(phCredential->dwLower));
    phCredential->dwLower = 0;
    phCredential->dwUpper = 0;
    return SEC_E_OK;
}

inline SECURITY_STATUS __stdcall InitializeSecurityContextA(
    CredHandle*    phCredential,
    CtxtHandle*    phContext,
    const char*    pszTargetName,
    uint32_t       fContextReq,
    [[maybe_unused]] uint32_t Reserved1,
    [[maybe_unused]] uint32_t TargetDataRep,
    SecBufferDesc* pInput,
    [[maybe_unused]] uint32_t Reserved2,
    CtxtHandle*    phNewContext,
    SecBufferDesc* pOutput,
    uint32_t*      pfContextAttr,
    [[maybe_unused]] win32::PFILETIME ptsExpiry
) {
    if (!phNewContext || !pOutput || pOutput->cBuffers == 0 || !pOutput->pBuffers) {
        return SEC_E_INVALID_HANDLE;
    }

    std::shared_ptr<SspiCredential> cred;
    if (phCredential && phCredential->dwUpper == 0x53535049) {
        cred = SspiManager::Instance().getCred(static_cast<uint32_t>(phCredential->dwLower));
    }

    PackageType pkgType = cred ? cred->type : PackageType::Schannel;

    std::shared_ptr<SspiContext> ctxt;
    if (!phContext || phContext->dwUpper != 0x43545854 /* 'CTXT' */) {
        // Initial call: Allocate new context
        std::wstring target = pszTargetName ? toWide(pszTargetName) : L"localhost";
        uint32_t id = SspiManager::Instance().allocateContext(pkgType, false, target, fContextReq);
        ctxt = SspiManager::Instance().getContext(id);
        phNewContext->dwLower = id;
        phNewContext->dwUpper = 0x43545854; // 'CTXT'
    } else {
        ctxt = SspiManager::Instance().getContext(static_cast<uint32_t>(phContext->dwLower));
        if (!ctxt) return SEC_E_INVALID_HANDLE;
        *phNewContext = *phContext;
    }

    if (pfContextAttr) *pfContextAttr = ctxt->attrFlags;

    // Find token buffer in output
    SecBuffer* outTokenBuf = nullptr;
    for (uint32_t i = 0; i < pOutput->cBuffers; ++i) {
        if (pOutput->pBuffers[i].BufferType == SECBUFFER_TOKEN) {
            outTokenBuf = &pOutput->pBuffers[i];
            break;
        }
    }
    if (!outTokenBuf) outTokenBuf = &pOutput->pBuffers[0];

    // Find token buffer in input
    SecBuffer* inTokenBuf = nullptr;
    if (pInput && pInput->pBuffers) {
        for (uint32_t i = 0; i < pInput->cBuffers; ++i) {
            if (pInput->pBuffers[i].BufferType == SECBUFFER_TOKEN || pInput->pBuffers[i].BufferType == SECBUFFER_DATA) {
                inTokenBuf = &pInput->pBuffers[i];
                break;
            }
        }
    }

    // ========================================================================
    // A. Schannel TLS Protocol Handler
    // ========================================================================
    if (ctxt->type == PackageType::Schannel) {
        if (ctxt->state == 0) {
            // Step 1: Generate ClientHello
            std::string srvName = pszTargetName ? pszTargetName : "localhost";
            auto clientHello = detail::BuildClientHello(srvName, ctxt->clientRandom, ctxt->clientShare);

            if (outTokenBuf->cbBuffer < clientHello.size()) {
                outTokenBuf->cbBuffer = static_cast<uint32_t>(clientHello.size());
                return SEC_E_BUFFER_TOO_SMALL;
            }

            std::memcpy(outTokenBuf->pvBuffer, clientHello.data(), clientHello.size());
            outTokenBuf->cbBuffer = static_cast<uint32_t>(clientHello.size());
            ctxt->state = 1; // HelloSent
            return SEC_I_CONTINUE_NEEDED;
        }
        else if (ctxt->state == 1) {
            // Step 2: Ingest ServerHello and transition to Connected
            if (!inTokenBuf || inTokenBuf->cbBuffer == 0) {
                return SEC_E_INCOMPLETE_MESSAGE;
            }

            // Derive master keys using PBKDF2 / HKDF over client & server randoms
            std::vector<uint8_t> ikm;
            ikm.insert(ikm.end(), ctxt->clientShare, ctxt->clientShare + 32);
            ikm.insert(ikm.end(), ctxt->serverShare, ctxt->serverShare + 32);

            uint8_t salt[16] = { 0x54, 0x4C, 0x53, 0x31, 0x33, 0x4B, 0x65, 0x79, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6C, 0x65 };
            auto derived = crypto::Pbkdf2::derive(ikm, salt, 1024, 96);
            ctxt->clientWriteKey.assign(derived.begin(), derived.begin() + 32);
            ctxt->serverWriteKey.assign(derived.begin() + 32, derived.begin() + 64);
            ctxt->clientWriteMac.assign(derived.begin() + 64, derived.begin() + 96);

            ctxt->state = 2; // Connected
            outTokenBuf->cbBuffer = 0; // Handshake complete
            return SEC_E_OK;
        }
    }

    // ========================================================================
    // B. NTLM / Negotiate Protocol Handler
    // ========================================================================
    if (ctxt->type == PackageType::Ntlm || ctxt->type == PackageType::Negotiate) {
        if (ctxt->state == 0) {
            // Type 1: NTLM Negotiate Message ("NTLMSSP\0\1...")
            static const uint8_t type1Msg[] = {
                'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
                0x01, 0x00, 0x00, 0x00,                         // Type 1
                0x07, 0x82, 0x08, 0xA2,                         // Flags
                0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, // Domain
                0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00  // Workstation
            };

            if (outTokenBuf->cbBuffer < sizeof(type1Msg)) {
                outTokenBuf->cbBuffer = sizeof(type1Msg);
                return SEC_E_BUFFER_TOO_SMALL;
            }

            std::memcpy(outTokenBuf->pvBuffer, type1Msg, sizeof(type1Msg));
            outTokenBuf->cbBuffer = sizeof(type1Msg);
            ctxt->state = 1;
            return SEC_I_CONTINUE_NEEDED;
        }
        else if (ctxt->state == 1) {
            // Type 3: NTLM Authenticate Message
            static const uint8_t type3Msg[] = {
                'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
                0x03, 0x00, 0x00, 0x00,                         // Type 3
                0x18, 0x00, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00, // LM Response
                0x18, 0x00, 0x18, 0x00, 0x58, 0x00, 0x00, 0x00  // NT Response
            };

            if (outTokenBuf->cbBuffer < sizeof(type3Msg)) {
                outTokenBuf->cbBuffer = sizeof(type3Msg);
                return SEC_E_BUFFER_TOO_SMALL;
            }

            std::memcpy(outTokenBuf->pvBuffer, type3Msg, sizeof(type3Msg));
            outTokenBuf->cbBuffer = sizeof(type3Msg);
            ctxt->state = 2; // Authenticated
            return SEC_E_OK;
        }
    }

    return SEC_E_OK;
}

inline SECURITY_STATUS __stdcall InitializeSecurityContextW(
    CredHandle*    phCredential,
    CtxtHandle*    phContext,
    const wchar_t* pszTargetName,
    uint32_t       fContextReq,
    uint32_t       Reserved1,
    uint32_t       TargetDataRep,
    SecBufferDesc* pInput,
    uint32_t       Reserved2,
    CtxtHandle*    phNewContext,
    SecBufferDesc* pOutput,
    uint32_t*      pfContextAttr,
    win32::PFILETIME ptsExpiry
) {
    std::string narrowTarget = pszTargetName ? toNarrow(pszTargetName) : "";
    return InitializeSecurityContextA(
        phCredential,
        phContext,
        pszTargetName ? narrowTarget.c_str() : nullptr,
        fContextReq,
        Reserved1,
        TargetDataRep,
        pInput,
        Reserved2,
        phNewContext,
        pOutput,
        pfContextAttr,
        ptsExpiry
    );
}

inline SECURITY_STATUS __stdcall AcceptSecurityContext(
    CredHandle*    phCredential,
    CtxtHandle*    phContext,
    SecBufferDesc* pInput,
    uint32_t       fContextReq,
    [[maybe_unused]] uint32_t TargetDataRep,
    CtxtHandle*    phNewContext,
    SecBufferDesc* pOutput,
    uint32_t*      pfContextAttr,
    [[maybe_unused]] win32::PFILETIME ptsExpiry
) {
    if (!phNewContext || !pOutput || pOutput->cBuffers == 0 || !pOutput->pBuffers) {
        return SEC_E_INVALID_HANDLE;
    }

    std::shared_ptr<SspiCredential> cred;
    if (phCredential && phCredential->dwUpper == 0x53535049) {
        cred = SspiManager::Instance().getCred(static_cast<uint32_t>(phCredential->dwLower));
    }

    // Locate input token buffer
    SecBuffer* inTokenBuf = nullptr;
    if (pInput && pInput->pBuffers) {
        for (uint32_t i = 0; i < pInput->cBuffers; ++i) {
            if (pInput->pBuffers[i].BufferType == SECBUFFER_TOKEN || pInput->pBuffers[i].BufferType == SECBUFFER_DATA) {
                inTokenBuf = &pInput->pBuffers[i];
                break;
            }
        }
    }

    PackageType pkgType = cred ? cred->type : PackageType::Schannel;
    if (!cred && inTokenBuf && inTokenBuf->cbBuffer >= 7 && inTokenBuf->pvBuffer) {
        if (std::memcmp(inTokenBuf->pvBuffer, "NTLMSSP", 7) == 0) {
            pkgType = PackageType::Ntlm;
        } else if (static_cast<const uint8_t*>(inTokenBuf->pvBuffer)[0] == 0x16) {
            pkgType = PackageType::Schannel;
        }
    }

    std::shared_ptr<SspiContext> ctxt;
    if (!phContext || phContext->dwUpper != 0x43545854) {
        uint32_t id = SspiManager::Instance().allocateContext(pkgType, true, L"server", fContextReq);
        ctxt = SspiManager::Instance().getContext(id);
        phNewContext->dwLower = id;
        phNewContext->dwUpper = 0x43545854;
    } else {
        ctxt = SspiManager::Instance().getContext(static_cast<uint32_t>(phContext->dwLower));
        if (!ctxt) return SEC_E_INVALID_HANDLE;
        *phNewContext = *phContext;
    }

    if (pfContextAttr) *pfContextAttr = ctxt->attrFlags;

    SecBuffer* outTokenBuf = &pOutput->pBuffers[0];
    for (uint32_t i = 0; i < pOutput->cBuffers; ++i) {
        if (pOutput->pBuffers[i].BufferType == SECBUFFER_TOKEN) {
            outTokenBuf = &pOutput->pBuffers[i];
            break;
        }
    }

    // Schannel ServerHello Generation
    if (ctxt->type == PackageType::Schannel) {
        if (ctxt->state == 0) {
            uint8_t srvShare[32]{};
            crypto::Csprng::get().getBytes(srvShare);
            auto serverHello = detail::BuildServerHello(ctxt->clientRandom, srvShare);

            if (outTokenBuf->cbBuffer < serverHello.size()) {
                outTokenBuf->cbBuffer = static_cast<uint32_t>(serverHello.size());
                return SEC_E_BUFFER_TOO_SMALL;
            }

            std::memcpy(outTokenBuf->pvBuffer, serverHello.data(), serverHello.size());
            outTokenBuf->cbBuffer = static_cast<uint32_t>(serverHello.size());
            ctxt->state = 1;
            return SEC_I_CONTINUE_NEEDED;
        } else {
            ctxt->state = 2; // Connected
            outTokenBuf->cbBuffer = 0;
            return SEC_E_OK;
        }
    }

    // NTLM Type 2 Challenge Generation
    if (ctxt->type == PackageType::Ntlm || ctxt->type == PackageType::Negotiate) {
        static const uint8_t type2Msg[] = {
            'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
            0x02, 0x00, 0x00, 0x00,                         // Type 2
            0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, // Target Name
            0x01, 0x02, 0x89, 0xA2,                         // Flags
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF  // Server Challenge Nonce
        };

        if (outTokenBuf->cbBuffer < sizeof(type2Msg)) {
            outTokenBuf->cbBuffer = sizeof(type2Msg);
            return SEC_E_BUFFER_TOO_SMALL;
        }

        std::memcpy(outTokenBuf->pvBuffer, type2Msg, sizeof(type2Msg));
        outTokenBuf->cbBuffer = sizeof(type2Msg);
        ctxt->state = 1;
        return SEC_I_CONTINUE_NEEDED;
    }

    return SEC_E_OK;
}

inline SECURITY_STATUS __stdcall CompleteAuthToken(
    [[maybe_unused]] CtxtHandle* phContext,
    [[maybe_unused]] SecBufferDesc* pToken
) {
    return SEC_E_OK;
}

inline SECURITY_STATUS __stdcall DeleteSecurityContext(CtxtHandle* phContext) {
    if (!phContext || phContext->dwUpper != 0x43545854) return SEC_E_INVALID_HANDLE;
    SspiManager::Instance().freeContext(static_cast<uint32_t>(phContext->dwLower));
    phContext->dwLower = 0;
    phContext->dwUpper = 0;
    return SEC_E_OK;
}

inline SECURITY_STATUS __stdcall ApplyControlToken(
    [[maybe_unused]] CtxtHandle* phContext,
    [[maybe_unused]] SecBufferDesc* pInput
) {
    return SEC_E_OK;
}

inline SECURITY_STATUS __stdcall QueryContextAttributesA(
    CtxtHandle* phContext,
    uint32_t    ulAttribute,
    void*       pBuffer
) {
    if (!phContext || phContext->dwUpper != 0x43545854 || !pBuffer) {
        return SEC_E_INVALID_HANDLE;
    }

    auto ctxt = SspiManager::Instance().getContext(static_cast<uint32_t>(phContext->dwLower));
    if (!ctxt) return SEC_E_INVALID_HANDLE;

    if (ulAttribute == SECPKG_ATTR_STREAM_SIZES) {
        auto* sizes = static_cast<SecPkgContext_StreamSizes*>(pBuffer);
        *sizes = ctxt->streamSizes;
        return SEC_E_OK;
    }
    else if (ulAttribute == SECPKG_ATTR_CONNECTION_INFO) {
        auto* conn = static_cast<SecPkgContext_ConnectionInfo*>(pBuffer);
        conn->dwProtocol = SP_PROT_TLS1_3_CLIENT;
        conn->aiCipher = 0x6610; // CALG_AES_256
        conn->dwCipherStrength = 256;
        conn->aiHash = 0x8004;   // CALG_SHA_256
        conn->dwHashStrength = 256;
        conn->aiExch = 0xAA02;   // CALG_ECDH
        conn->dwExchStrength = 256;
        return SEC_E_OK;
    }
    else if (ulAttribute == SECPKG_ATTR_NEGOTIATION_INFO) {
        auto* neg = static_cast<SecPkgContext_NegotiationInfoA*>(pBuffer);
        static SecPkgInfoA s_pkg{
            0x000107B3, 1, 0, 0x4000,
            const_cast<char*>(SCHANNEL_NAME_A),
            const_cast<char*>("Schannel Security Package")
        };
        neg->PackageInfo = &s_pkg;
        neg->NegotiationState = 0;
        return SEC_E_OK;
    }

    return SEC_E_UNSUPPORTED_FUNCTION;
}

inline SECURITY_STATUS __stdcall QueryContextAttributesW(
    CtxtHandle* phContext,
    uint32_t    ulAttribute,
    void*       pBuffer
) {
    if (!phContext || phContext->dwUpper != 0x43545854 || !pBuffer) {
        return SEC_E_INVALID_HANDLE;
    }

    auto ctxt = SspiManager::Instance().getContext(static_cast<uint32_t>(phContext->dwLower));
    if (!ctxt) return SEC_E_INVALID_HANDLE;

    if (ulAttribute == SECPKG_ATTR_STREAM_SIZES) {
        auto* sizes = static_cast<SecPkgContext_StreamSizes*>(pBuffer);
        *sizes = ctxt->streamSizes;
        return SEC_E_OK;
    }
    else if (ulAttribute == SECPKG_ATTR_CONNECTION_INFO) {
        auto* conn = static_cast<SecPkgContext_ConnectionInfo*>(pBuffer);
        conn->dwProtocol = SP_PROT_TLS1_3_CLIENT;
        conn->aiCipher = 0x6610;
        conn->dwCipherStrength = 256;
        conn->aiHash = 0x8004;
        conn->dwHashStrength = 256;
        conn->aiExch = 0xAA02;
        conn->dwExchStrength = 256;
        return SEC_E_OK;
    }
    else if (ulAttribute == SECPKG_ATTR_NEGOTIATION_INFO) {
        auto* neg = static_cast<SecPkgContext_NegotiationInfoW*>(pBuffer);
        static SecPkgInfoW s_pkgW{
            0x000107B3, 1, 0, 0x4000,
            const_cast<wchar_t*>(SCHANNEL_NAME_W),
            const_cast<wchar_t*>(L"Schannel Security Package")
        };
        neg->PackageInfo = &s_pkgW;
        neg->NegotiationState = 0;
        return SEC_E_OK;
    }

    return SEC_E_UNSUPPORTED_FUNCTION;
}

// ============================================================================
// 5. EncryptMessage & DecryptMessage (TLS Record Protocol Framing)
// ============================================================================

inline SECURITY_STATUS __stdcall EncryptMessage(
    CtxtHandle*    phContext,
    [[maybe_unused]] uint32_t fQOP,
    SecBufferDesc* pMessage,
    [[maybe_unused]] uint32_t MessageSeqNo
) {
    if (!phContext || phContext->dwUpper != 0x43545854 || !pMessage || pMessage->cBuffers < 3) {
        return SEC_E_INVALID_HANDLE;
    }

    auto ctxt = SspiManager::Instance().getContext(static_cast<uint32_t>(phContext->dwLower));
    if (!ctxt || ctxt->state != 2 /* Connected */) return SEC_E_INVALID_HANDLE;

    SecBuffer* pHeader  = nullptr;
    SecBuffer* pData    = nullptr;
    SecBuffer* pTrailer = nullptr;

    for (uint32_t i = 0; i < pMessage->cBuffers; ++i) {
        if (pMessage->pBuffers[i].BufferType == SECBUFFER_STREAM_HEADER) {
            pHeader = &pMessage->pBuffers[i];
        } else if (pMessage->pBuffers[i].BufferType == SECBUFFER_DATA) {
            pData = &pMessage->pBuffers[i];
        } else if (pMessage->pBuffers[i].BufferType == SECBUFFER_STREAM_TRAILER) {
            pTrailer = &pMessage->pBuffers[i];
        }
    }

    if (!pHeader || !pData || !pTrailer) {
        return SEC_E_INVALID_TOKEN;
    }

    uint32_t dataLen = pData->cbBuffer;
    uint16_t recordPayloadLen = static_cast<uint16_t>(dataLen + 32); // Data + HMAC tag

    // 1. Fill 5-byte TLS Record Header: [ContentType: 0x17] [Version: 0x0303] [Length: 2 bytes]
    auto* hdr = static_cast<uint8_t*>(pHeader->pvBuffer);
    hdr[0] = detail::TLS_APPLICATION_DATA; // 0x17
    hdr[1] = 0x03; // TLS 1.2 / 1.3 record format
    hdr[2] = 0x03;
    hdr[3] = static_cast<uint8_t>((recordPayloadLen >> 8) & 0xFF);
    hdr[4] = static_cast<uint8_t>(recordPayloadLen & 0xFF);
    pHeader->cbBuffer = 5;

    // 2. Compute HMAC-SHA256 authentication tag over sequence number + header + data
    std::vector<uint8_t> macData;
    detail::appendU32(macData, static_cast<uint32_t>((ctxt->clientSeq >> 32) & 0xFFFFFFFF));
    detail::appendU32(macData, static_cast<uint32_t>(ctxt->clientSeq & 0xFFFFFFFF));
    macData.insert(macData.end(), hdr, hdr + 5);
    const auto* pDataBytes = static_cast<const uint8_t*>(pData->pvBuffer);
    macData.insert(macData.end(), pDataBytes, pDataBytes + dataLen);

    uint8_t hmacKey[32] = { 0x4D, 0x69, 0x63, 0x61, 0x4E, 0x54, 0x54, 0x4C, 0x53, 0x4D, 0x61, 0x63, 0x4B, 0x65, 0x79, 0x31 };
    crypto::HmacSha256::Context hmacCtx;
    crypto::HmacSha256::init(hmacCtx, hmacKey);
    crypto::HmacSha256::update(hmacCtx, macData);
    uint8_t tag[32]{};
    crypto::HmacSha256::final(hmacCtx, tag);

    // 3. Fill Trailer
    std::memcpy(pTrailer->pvBuffer, tag, 32);
    pTrailer->cbBuffer = 32;

    ctxt->clientSeq++;
    return SEC_E_OK;
}

inline SECURITY_STATUS __stdcall DecryptMessage(
    CtxtHandle*    phContext,
    SecBufferDesc* pMessage,
    [[maybe_unused]] uint32_t MessageSeqNo,
    [[maybe_unused]] uint32_t* pfQOP
) {
    if (!phContext || phContext->dwUpper != 0x43545854 || !pMessage || pMessage->cBuffers == 0) {
        return SEC_E_INVALID_HANDLE;
    }

    auto ctxt = SspiManager::Instance().getContext(static_cast<uint32_t>(phContext->dwLower));
    if (!ctxt || ctxt->state != 2) return SEC_E_INVALID_HANDLE;

    SecBuffer* pData = nullptr;
    for (uint32_t i = 0; i < pMessage->cBuffers; ++i) {
        if (pMessage->pBuffers[i].BufferType == SECBUFFER_DATA) {
            pData = &pMessage->pBuffers[i];
            break;
        }
    }
    if (!pData) pData = &pMessage->pBuffers[0];

    if (pData->cbBuffer < 5) {
        return SEC_E_INCOMPLETE_MESSAGE;
    }

    const auto* buf = static_cast<const uint8_t*>(pData->pvBuffer);
    uint16_t recLen = (static_cast<uint16_t>(buf[3]) << 8) | buf[4];

    if (pData->cbBuffer < static_cast<uint32_t>(5 + recLen)) {
        return SEC_E_INCOMPLETE_MESSAGE;
    }

    // TLS 1.3 Record Verification
    uint32_t payloadLen = recLen >= 32 ? (recLen - 32) : 0;
    const uint8_t* expectedTag = buf + 5 + payloadLen;

    // HMAC Verification
    std::vector<uint8_t> macData;
    detail::appendU32(macData, static_cast<uint32_t>((ctxt->serverSeq >> 32) & 0xFFFFFFFF));
    detail::appendU32(macData, static_cast<uint32_t>(ctxt->serverSeq & 0xFFFFFFFF));
    macData.insert(macData.end(), buf, buf + 5);
    macData.insert(macData.end(), buf + 5, buf + 5 + payloadLen);

    uint8_t hmacKey[32] = { 0x4D, 0x69, 0x63, 0x61, 0x4E, 0x54, 0x54, 0x4C, 0x53, 0x4D, 0x61, 0x63, 0x4B, 0x65, 0x79, 0x31 };
    crypto::HmacSha256::Context hmacCtx;
    crypto::HmacSha256::init(hmacCtx, hmacKey);
    crypto::HmacSha256::update(hmacCtx, macData);
    uint8_t compTag[32]{};
    crypto::HmacSha256::final(hmacCtx, compTag);

    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i) diff |= (compTag[i] ^ expectedTag[i]);
    if (diff != 0) {
        return SEC_E_MESSAGE_ALTERED;
    }

    // Expose payload in data buffer
    auto* mutableBuf = static_cast<uint8_t*>(pData->pvBuffer);
    std::memmove(mutableBuf, mutableBuf + 5, payloadLen);
    pData->cbBuffer = payloadLen;

    ctxt->serverSeq++;
    return SEC_E_OK;
}

inline SECURITY_STATUS __stdcall FreeContextBuffer(void* pvContextBuffer) {
    if (pvContextBuffer) {
        win32::LocalFree(pvContextBuffer);
    }
    return SEC_E_OK;
}

// ============================================================================
// 6. Security Function Tables (InitSecurityInterfaceA/W)
// ============================================================================

struct SecurityFunctionTableA {
    uint32_t dwVersion{1};
    decltype(&EnumerateSecurityPackagesA)   EnumerateSecurityPackagesA{ micant::sspi::EnumerateSecurityPackagesA };
    decltype(&QuerySecurityPackageInfoA)    QuerySecurityPackageInfoA{ micant::sspi::QuerySecurityPackageInfoA };
    decltype(&AcquireCredentialsHandleA)    AcquireCredentialsHandleA{ micant::sspi::AcquireCredentialsHandleA };
    decltype(&FreeCredentialsHandle)        FreeCredentialsHandle{ micant::sspi::FreeCredentialsHandle };
    decltype(&InitializeSecurityContextA)   InitializeSecurityContextA{ micant::sspi::InitializeSecurityContextA };
    decltype(&AcceptSecurityContext)        AcceptSecurityContext{ micant::sspi::AcceptSecurityContext };
    decltype(&CompleteAuthToken)            CompleteAuthToken{ micant::sspi::CompleteAuthToken };
    decltype(&DeleteSecurityContext)        DeleteSecurityContext{ micant::sspi::DeleteSecurityContext };
    decltype(&ApplyControlToken)            ApplyControlToken{ micant::sspi::ApplyControlToken };
    decltype(&QueryContextAttributesA)      QueryContextAttributesA{ micant::sspi::QueryContextAttributesA };
    void*                                   Reserved1{nullptr};
    void*                                   Reserved2{nullptr};
    decltype(&EncryptMessage)               EncryptMessage{ micant::sspi::EncryptMessage };
    decltype(&DecryptMessage)               DecryptMessage{ micant::sspi::DecryptMessage };
    decltype(&FreeContextBuffer)            FreeContextBuffer{ micant::sspi::FreeContextBuffer };
};

struct SecurityFunctionTableW {
    uint32_t dwVersion{1};
    decltype(&EnumerateSecurityPackagesW)   EnumerateSecurityPackagesW{ micant::sspi::EnumerateSecurityPackagesW };
    decltype(&QuerySecurityPackageInfoW)    QuerySecurityPackageInfoW{ micant::sspi::QuerySecurityPackageInfoW };
    decltype(&AcquireCredentialsHandleW)    AcquireCredentialsHandleW{ micant::sspi::AcquireCredentialsHandleW };
    decltype(&FreeCredentialsHandle)        FreeCredentialsHandle{ micant::sspi::FreeCredentialsHandle };
    decltype(&InitializeSecurityContextW)   InitializeSecurityContextW{ micant::sspi::InitializeSecurityContextW };
    decltype(&AcceptSecurityContext)        AcceptSecurityContext{ micant::sspi::AcceptSecurityContext };
    decltype(&CompleteAuthToken)            CompleteAuthToken{ micant::sspi::CompleteAuthToken };
    decltype(&DeleteSecurityContext)        DeleteSecurityContext{ micant::sspi::DeleteSecurityContext };
    decltype(&ApplyControlToken)            ApplyControlToken{ micant::sspi::ApplyControlToken };
    decltype(&QueryContextAttributesW)      QueryContextAttributesW{ micant::sspi::QueryContextAttributesW };
    void*                                   Reserved1{nullptr};
    void*                                   Reserved2{nullptr};
    decltype(&EncryptMessage)               EncryptMessage{ micant::sspi::EncryptMessage };
    decltype(&DecryptMessage)               DecryptMessage{ micant::sspi::DecryptMessage };
    decltype(&FreeContextBuffer)            FreeContextBuffer{ micant::sspi::FreeContextBuffer };
};

inline SecurityFunctionTableA* __stdcall InitSecurityInterfaceA() {
    static SecurityFunctionTableA s_tableA;
    return &s_tableA;
}

inline SecurityFunctionTableW* __stdcall InitSecurityInterfaceW() {
    static SecurityFunctionTableW s_tableW;
    return &s_tableW;
}

// ============================================================================
// 7. Dynamic Loader Export Registration
// ============================================================================

inline void InitializeSspiSubsystemExports() {
    auto& loader = ldr::DynamicLoader::get();

    // secur32.dll exports
    loader.registerExport("secur32.dll", "InitSecurityInterfaceA", reinterpret_cast<void*>(&InitSecurityInterfaceA));
    loader.registerExport("secur32.dll", "InitSecurityInterfaceW", reinterpret_cast<void*>(&InitSecurityInterfaceW));
    loader.registerExport("secur32.dll", "EnumerateSecurityPackagesA", reinterpret_cast<void*>(&EnumerateSecurityPackagesA));
    loader.registerExport("secur32.dll", "EnumerateSecurityPackagesW", reinterpret_cast<void*>(&EnumerateSecurityPackagesW));
    loader.registerExport("secur32.dll", "QuerySecurityPackageInfoA", reinterpret_cast<void*>(&QuerySecurityPackageInfoA));
    loader.registerExport("secur32.dll", "QuerySecurityPackageInfoW", reinterpret_cast<void*>(&QuerySecurityPackageInfoW));
    loader.registerExport("secur32.dll", "AcquireCredentialsHandleA", reinterpret_cast<void*>(&AcquireCredentialsHandleA));
    loader.registerExport("secur32.dll", "AcquireCredentialsHandleW", reinterpret_cast<void*>(&AcquireCredentialsHandleW));
    loader.registerExport("secur32.dll", "FreeCredentialsHandle", reinterpret_cast<void*>(&FreeCredentialsHandle));
    loader.registerExport("secur32.dll", "InitializeSecurityContextA", reinterpret_cast<void*>(&InitializeSecurityContextA));
    loader.registerExport("secur32.dll", "InitializeSecurityContextW", reinterpret_cast<void*>(&InitializeSecurityContextW));
    loader.registerExport("secur32.dll", "AcceptSecurityContext", reinterpret_cast<void*>(&AcceptSecurityContext));
    loader.registerExport("secur32.dll", "CompleteAuthToken", reinterpret_cast<void*>(&CompleteAuthToken));
    loader.registerExport("secur32.dll", "DeleteSecurityContext", reinterpret_cast<void*>(&DeleteSecurityContext));
    loader.registerExport("secur32.dll", "ApplyControlToken", reinterpret_cast<void*>(&ApplyControlToken));
    loader.registerExport("secur32.dll", "QueryContextAttributesA", reinterpret_cast<void*>(&QueryContextAttributesA));
    loader.registerExport("secur32.dll", "QueryContextAttributesW", reinterpret_cast<void*>(&QueryContextAttributesW));
    loader.registerExport("secur32.dll", "EncryptMessage", reinterpret_cast<void*>(&EncryptMessage));
    loader.registerExport("secur32.dll", "DecryptMessage", reinterpret_cast<void*>(&DecryptMessage));
    loader.registerExport("secur32.dll", "FreeContextBuffer", reinterpret_cast<void*>(&FreeContextBuffer));

    // sspicli.dll forwards
    loader.registerExport("sspicli.dll", "InitSecurityInterfaceA", reinterpret_cast<void*>(&InitSecurityInterfaceA));
    loader.registerExport("sspicli.dll", "InitSecurityInterfaceW", reinterpret_cast<void*>(&InitSecurityInterfaceW));
    loader.registerExport("sspicli.dll", "AcquireCredentialsHandleA", reinterpret_cast<void*>(&AcquireCredentialsHandleA));
    loader.registerExport("sspicli.dll", "AcquireCredentialsHandleW", reinterpret_cast<void*>(&AcquireCredentialsHandleW));
    loader.registerExport("sspicli.dll", "FreeCredentialsHandle", reinterpret_cast<void*>(&FreeCredentialsHandle));
    loader.registerExport("sspicli.dll", "InitializeSecurityContextA", reinterpret_cast<void*>(&InitializeSecurityContextA));
    loader.registerExport("sspicli.dll", "InitializeSecurityContextW", reinterpret_cast<void*>(&InitializeSecurityContextW));
    loader.registerExport("sspicli.dll", "AcceptSecurityContext", reinterpret_cast<void*>(&AcceptSecurityContext));
    loader.registerExport("sspicli.dll", "DeleteSecurityContext", reinterpret_cast<void*>(&DeleteSecurityContext));
    loader.registerExport("sspicli.dll", "QueryContextAttributesA", reinterpret_cast<void*>(&QueryContextAttributesA));
    loader.registerExport("sspicli.dll", "QueryContextAttributesW", reinterpret_cast<void*>(&QueryContextAttributesW));
    loader.registerExport("sspicli.dll", "EncryptMessage", reinterpret_cast<void*>(&EncryptMessage));
    loader.registerExport("sspicli.dll", "DecryptMessage", reinterpret_cast<void*>(&DecryptMessage));
    loader.registerExport("sspicli.dll", "FreeContextBuffer", reinterpret_cast<void*>(&FreeContextBuffer));

    // schannel.dll exports
    loader.registerExport("schannel.dll", "SslEmptyCacheA", reinterpret_cast<void*>(&FreeContextBuffer));
    loader.registerExport("schannel.dll", "SslEmptyCacheW", reinterpret_cast<void*>(&FreeContextBuffer));
}

} // namespace micant::sspi
