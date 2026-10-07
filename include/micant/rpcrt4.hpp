// ============================================================================
// MicaNT: Sovereign Operating System Executive
// include/micant/rpcrt4.hpp - Windows Remote Procedure Call (RPC) Runtime
// & Network Data Representation (NDR) Subsystem (rpcrt4.dll)
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
#include <functional>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "kernel32.hpp"
#include "cipherksp.hpp"
#include "lpc.hpp"
#include "npfs.hpp"
#include "ws2_32.hpp"
#include "tcpip.hpp"
#include "ldr.hpp"

namespace micant::rpc {

// ============================================================================
// 1. RPC Status Codes & Constants
// ============================================================================

using RPC_STATUS = int32_t;

inline constexpr RPC_STATUS RPC_S_OK                          = 0;
inline constexpr RPC_STATUS RPC_S_INVALID_ARG                 = 87;
inline constexpr RPC_STATUS RPC_S_INVALID_STRING_BINDING      = 1700;
inline constexpr RPC_STATUS RPC_S_WRONG_KIND_OF_BINDING       = 1701;
inline constexpr RPC_STATUS RPC_S_INVALID_BINDING             = 1702;
inline constexpr RPC_STATUS RPC_S_PROTSEQ_NOT_SUPPORTED       = 1703;
inline constexpr RPC_STATUS RPC_S_INVALID_RPC_PROTSEQ         = 1704;
inline constexpr RPC_STATUS RPC_S_INVALID_STRING_UUID         = 1705;
inline constexpr RPC_STATUS RPC_S_INVALID_ENDPOINT_FORMAT     = 1706;
inline constexpr RPC_STATUS RPC_S_INVALID_NET_ADDR            = 1707;
inline constexpr RPC_STATUS RPC_S_NO_ENDPOINT_FOUND           = 1708;
inline constexpr RPC_STATUS RPC_S_INVALID_TIMEOUT             = 1709;
inline constexpr RPC_STATUS RPC_S_OBJECT_NOT_FOUND            = 1710;
inline constexpr RPC_STATUS RPC_S_ALREADY_REGISTERED          = 1711;
inline constexpr RPC_STATUS RPC_S_TYPE_ALREADY_REGISTERED     = 1712;
inline constexpr RPC_STATUS RPC_S_ALREADY_LISTENING           = 1713;
inline constexpr RPC_STATUS RPC_S_NO_PROTSEQS_REGISTERED      = 1714;
inline constexpr RPC_STATUS RPC_S_NOT_LISTENING               = 1715;
inline constexpr RPC_STATUS RPC_S_UNKNOWN_MGR_TYPE            = 1716;
inline constexpr RPC_STATUS RPC_S_UNKNOWN_IF                  = 1717;
inline constexpr RPC_STATUS RPC_S_NO_MORE_BINDINGS            = 1718;
inline constexpr RPC_STATUS RPC_S_NO_MORE_MEMBERS             = 1719;
inline constexpr RPC_STATUS RPC_S_NOT_ALL_OBJS_UNREGISTERED   = 1720;
inline constexpr RPC_STATUS RPC_S_INTERFACE_NOT_FOUND         = 1721;
inline constexpr RPC_STATUS RPC_S_ENTRY_ALREADY_EXISTS        = 1722;
inline constexpr RPC_STATUS RPC_S_ENTRY_NOT_FOUND             = 1723;
inline constexpr RPC_STATUS RPC_S_NAME_SERVICE_UNAVAILABLE    = 1724;
inline constexpr RPC_STATUS RPC_S_INVALID_NAF_ID              = 1725;
inline constexpr RPC_STATUS RPC_S_CANNOT_SUPPORT              = 1726;
inline constexpr RPC_STATUS RPC_S_NO_CONTEXT_AVAILABLE        = 1727;
inline constexpr RPC_STATUS RPC_S_INTERNAL_ERROR              = 1728;
inline constexpr RPC_STATUS RPC_S_SERVER_UNAVAILABLE          = 1722;
inline constexpr RPC_STATUS RPC_S_SERVER_TOO_BUSY             = 1723;
inline constexpr RPC_STATUS RPC_S_CALL_FAILED                 = 1726;
inline constexpr RPC_STATUS RPC_S_DUPLICATE_ENDPOINT          = 1740;
inline constexpr RPC_STATUS RPC_S_CALL_IN_PROGRESS            = 1791;
inline constexpr RPC_STATUS RPC_S_PROTOCOL_ERROR              = 1728;
inline constexpr RPC_STATUS RPC_X_BAD_STUB_DATA               = 1783;
inline constexpr RPC_STATUS RPC_X_WRONG_STUB_VERSION          = 1823;

// Authentication Services
inline constexpr uint32_t RPC_C_AUTHN_NONE                    = 0;
inline constexpr uint32_t RPC_C_AUTHN_WINNT                   = 10;
inline constexpr uint32_t RPC_C_AUTHN_GSS_SCHANNEL            = 14;
inline constexpr uint32_t RPC_C_AUTHN_DEFAULT                 = 0xFFFFFFFF;

// Authentication Levels
inline constexpr uint32_t RPC_C_AUTHN_LEVEL_DEFAULT           = 0;
inline constexpr uint32_t RPC_C_AUTHN_LEVEL_NONE              = 1;
inline constexpr uint32_t RPC_C_AUTHN_LEVEL_CONNECT           = 2;
inline constexpr uint32_t RPC_C_AUTHN_LEVEL_CALL              = 3;
inline constexpr uint32_t RPC_C_AUTHN_LEVEL_PKT               = 4;
inline constexpr uint32_t RPC_C_AUTHN_LEVEL_PKT_INTEGRITY     = 5;
inline constexpr uint32_t RPC_C_AUTHN_LEVEL_PKT_PRIVACY       = 6;

// NDR Format Characters
inline constexpr uint8_t FC_ZERO                              = 0x00;
inline constexpr uint8_t FC_BYTE                              = 0x01;
inline constexpr uint8_t FC_CHAR                              = 0x02;
inline constexpr uint8_t FC_SMALL                             = 0x03;
inline constexpr uint8_t FC_USMALL                            = 0x04;
inline constexpr uint8_t FC_SHORT                             = 0x05;
inline constexpr uint8_t FC_USHORT                            = 0x06;
inline constexpr uint8_t FC_LONG                              = 0x07;
inline constexpr uint8_t FC_ULONG                             = 0x08;
inline constexpr uint8_t FC_FLOAT                             = 0x09;
inline constexpr uint8_t FC_HYPER                             = 0x0a;
inline constexpr uint8_t FC_DOUBLE                            = 0x0b;
inline constexpr uint8_t FC_ENUM16                            = 0x0c;
inline constexpr uint8_t FC_ENUM32                            = 0x0d;
inline constexpr uint8_t FC_IGNORE                            = 0x0e;
inline constexpr uint8_t FC_ERROR_STATUS_T                    = 0x0f;
inline constexpr uint8_t FC_RP                                = 0x11;
inline constexpr uint8_t FC_UP                                = 0x12;
inline constexpr uint8_t FC_OP                                = 0x13;
inline constexpr uint8_t FC_FP                                = 0x14;
inline constexpr uint8_t FC_STRUCT                            = 0x15;
inline constexpr uint8_t FC_PSTRUCT                           = 0x16;
inline constexpr uint8_t FC_CSTRUCT                           = 0x17;
inline constexpr uint8_t FC_CPSTRUCT                          = 0x18;
inline constexpr uint8_t FC_CVSTRUCT                          = 0x19;
inline constexpr uint8_t FC_BOGUS_STRUCT                      = 0x1a;
inline constexpr uint8_t FC_CARRAY                            = 0x1b;
inline constexpr uint8_t FC_CVARRAY                           = 0x1c;
inline constexpr uint8_t FC_SMFARRAY                          = 0x1d;
inline constexpr uint8_t FC_LGFARRAY                          = 0x1e;
inline constexpr uint8_t FC_SMVARRAY                          = 0x1f;
inline constexpr uint8_t FC_LGVARRAY                          = 0x20;
inline constexpr uint8_t FC_BOGUS_ARRAY                       = 0x21;
inline constexpr uint8_t FC_C_CSTRING                         = 0x22;
inline constexpr uint8_t FC_C_BSTRING                         = 0x23;
inline constexpr uint8_t FC_C_SSTRING                         = 0x24;
inline constexpr uint8_t FC_C_WSTRING                         = 0x25;
inline constexpr uint8_t FC_CSTRING                           = 0x26;
inline constexpr uint8_t FC_BSTRING                           = 0x27;
inline constexpr uint8_t FC_SSTRING                           = 0x28;
inline constexpr uint8_t FC_WSTRING                           = 0x29;

// ============================================================================
// 2. Fundamental RPC & NDR Structures
// ============================================================================

using RPC_BINDING_HANDLE = void*;
using RPC_IF_HANDLE = void*;

struct RPC_SYNTAX_IDENTIFIER {
    micant::GUID SyntaxGUID;
    struct {
        uint16_t MajorVersion{0};
        uint16_t MinorVersion{0};
    } SyntaxVersion;

    bool operator==(const RPC_SYNTAX_IDENTIFIER& o) const noexcept {
        return SyntaxGUID == o.SyntaxGUID &&
               SyntaxVersion.MajorVersion == o.SyntaxVersion.MajorVersion &&
               SyntaxVersion.MinorVersion == o.SyntaxVersion.MinorVersion;
    }
};

// Standard NDR 2.0 Transfer Syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860, v2.0
inline constexpr RPC_SYNTAX_IDENTIFIER NDR_TRANSFER_SYNTAX = {
    { 0x8a885d04, 0x1ceb, 0x11c9, { 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 } },
    { 2, 0 }
};

inline constexpr GUID NDR_TRANSFER_SYNTAX_GUID = {
    0x8a885d04, 0x1ceb, 0x11c9, { 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 }
};

struct RPC_PROTSEQ_ENDPOINT {
    unsigned char* RpcProtseq{nullptr};
    unsigned char* Endpoint{nullptr};
};

struct RPC_MESSAGE;
using RPC_DISPATCH_FUNCTION = void (__stdcall *)(RPC_MESSAGE*);

struct RPC_DISPATCH_TABLE {
    uint32_t DispatchTableCount{0};
    RPC_DISPATCH_FUNCTION* DispatchTable{nullptr};
    uintptr_t Reserved{0};
};

struct RPC_SERVER_INTERFACE {
    uint32_t Length{sizeof(RPC_SERVER_INTERFACE)};
    RPC_SYNTAX_IDENTIFIER InterfaceId{};
    RPC_SYNTAX_IDENTIFIER TransferSyntax{NDR_TRANSFER_SYNTAX};
    RPC_DISPATCH_TABLE* DispatchTable{nullptr};
    uint32_t RpcProtseqEndpointCount{0};
    RPC_PROTSEQ_ENDPOINT* RpcProtseqEndpoint{nullptr};
    void* DefaultManagerEpv{nullptr};
    void const* InterpreterInfo{nullptr};
    uint32_t Flags{0};
};

struct RPC_CLIENT_INTERFACE {
    uint32_t Length{sizeof(RPC_CLIENT_INTERFACE)};
    RPC_SYNTAX_IDENTIFIER InterfaceId{};
    RPC_SYNTAX_IDENTIFIER TransferSyntax{NDR_TRANSFER_SYNTAX};
    RPC_DISPATCH_TABLE* DispatchTable{nullptr};
    uint32_t RpcProtseqEndpointCount{0};
    RPC_PROTSEQ_ENDPOINT* RpcProtseqEndpoint{nullptr};
    uintptr_t Reserved{0};
    void const* InterpreterInfo{nullptr};
    uint32_t Flags{0};
};

struct RPC_MESSAGE {
    RPC_BINDING_HANDLE Handle{nullptr};
    uint32_t DataRepresentation{0x00000010}; // Little-Endian, ASCII, IEEE
    void* Buffer{nullptr};
    uint32_t BufferLength{0};
    uint32_t ProcNum{0};
    RPC_SYNTAX_IDENTIFIER* TransferSyntax{nullptr};
    void* RpcInterfaceInformation{nullptr};
    void* ReservedForRuntime{nullptr};
    void* ManagerEpv{nullptr};
    void* ImportContext{nullptr};
    uint32_t RpcFlags{0};
};

// Asynchronous RPC
enum RPC_NOTIFICATION_TYPES {
    RpcNotificationTypeNone = 0,
    RpcNotificationTypeEvent = 1,
    RpcNotificationTypeApc = 2,
    RpcNotificationTypeIocp = 3,
    RpcNotificationTypeHwnd = 4,
    RpcNotificationTypeCallback = 5
};

struct RPC_ASYNC_STATE {
    uint32_t Size{sizeof(RPC_ASYNC_STATE)};
    uint32_t Signature{0x4153594E}; // 'ASYN'
    int32_t  Lock{0};
    uint32_t Flags{0};
    void*    StubInfo{nullptr};
    void*    UserInfo{nullptr};
    void*    RuntimeInfo{nullptr};
    RPC_NOTIFICATION_TYPES NotificationType{RpcNotificationTypeNone};
    union {
        struct {
            void* NotificationRoutine;
            void* Call;
        } APC;
        struct {
            void* hIOPort;
            uint32_t dwNumberOfBytesTransferred;
            uintptr_t dwCompletionKey;
            void* lpOverlapped;
        } IOCP;
        struct {
            void* hWnd;
            uint32_t Msg;
        } HWND;
        void* hEvent;
        void* NotificationRoutine;
    } u{};
    uintptr_t Reserved[4]{0};
};

using PRPC_ASYNC_STATE = RPC_ASYNC_STATE*;

// ============================================================================
// 3. String & Encoding Helpers
// ============================================================================

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
// 4. UUID / GUID Operations (uuidgen / UuidCreate / UuidToString)
// ============================================================================

inline RPC_STATUS __stdcall UuidCreate(micant::UUID* pUuid) {
    if (!pUuid) return RPC_S_INTERNAL_ERROR;

    uint8_t randBytes[16]{};
    crypto::Csprng::get().getBytes(randBytes);

    std::memcpy(pUuid, randBytes, 16);

    // RFC 4122 Version 4 variant & version bits:
    // Version 4: Data3 bits 12-15 = 0100b
    pUuid->Data3 = (pUuid->Data3 & 0x0FFF) | 0x4000;
    // Variant 1: Data4[0] bits 6-7 = 10b
    pUuid->Data4[0] = (pUuid->Data4[0] & 0x3F) | 0x80;

    return RPC_S_OK;
}

inline RPC_STATUS __stdcall UuidCreateSequential(micant::UUID* pUuid) {
    if (!pUuid) return RPC_S_INTERNAL_ERROR;

    static std::atomic<uint64_t> s_seqCounter{1};
    uint64_t count = s_seqCounter.fetch_add(1);

    uint64_t nowTime = 133500000000000000ULL + count;
    pUuid->Data1 = static_cast<uint32_t>(nowTime & 0xFFFFFFFF);
    pUuid->Data2 = static_cast<uint16_t>((nowTime >> 32) & 0xFFFF);
    pUuid->Data3 = static_cast<uint16_t>(((nowTime >> 48) & 0x0FFF) | 0x1000); // Version 1

    pUuid->Data4[0] = 0x80; // Variant 1
    pUuid->Data4[1] = 0x00;
    pUuid->Data4[2] = 0x00; // Simulated MicaNT MAC Node
    pUuid->Data4[3] = 0x50;
    pUuid->Data4[4] = 0x56;
    pUuid->Data4[5] = 0x01;
    pUuid->Data4[6] = 0x02;
    pUuid->Data4[7] = 0x03;

    return RPC_S_OK;
}

inline RPC_STATUS __stdcall UuidToStringA(const micant::UUID* pUuid, unsigned char** pStringUuid) {
    if (!pUuid || !pStringUuid) return RPC_S_INVALID_STRING_UUID;

    char buf[64]{};
    std::snprintf(
        buf, sizeof(buf),
        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        pUuid->Data1, pUuid->Data2, pUuid->Data3,
        pUuid->Data4[0], pUuid->Data4[1],
        pUuid->Data4[2], pUuid->Data4[3], pUuid->Data4[4], pUuid->Data4[5], pUuid->Data4[6], pUuid->Data4[7]
    );

    size_t len = std::strlen(buf);
    auto* outStr = static_cast<unsigned char*>(win32::LocalAlloc(0x0040 /* LPTR */, len + 1));
    if (!outStr) return RPC_S_INTERNAL_ERROR;

    std::memcpy(outStr, buf, len + 1);
    *pStringUuid = outStr;
    return RPC_S_OK;
}

inline RPC_STATUS __stdcall UuidToStringW(const micant::UUID* pUuid, wchar_t** pStringUuid) {
    if (!pUuid || !pStringUuid) return RPC_S_INVALID_STRING_UUID;

    unsigned char* narrowStr = nullptr;
    RPC_STATUS st = UuidToStringA(pUuid, &narrowStr);
    if (st != RPC_S_OK) return st;

    std::string s(reinterpret_cast<char*>(narrowStr));
    win32::LocalFree(narrowStr);

    std::wstring ws = toWide(s);
    auto* outWStr = static_cast<wchar_t*>(win32::LocalAlloc(0x0040, (ws.size() + 1) * sizeof(wchar_t)));
    if (!outWStr) return RPC_S_INTERNAL_ERROR;

    std::memcpy(outWStr, ws.c_str(), (ws.size() + 1) * sizeof(wchar_t));
    *pStringUuid = outWStr;
    return RPC_S_OK;
}

inline RPC_STATUS __stdcall UuidFromStringA(unsigned char* StringUuid, micant::UUID* pUuid) {
    if (!StringUuid || !pUuid) return RPC_S_INVALID_STRING_UUID;

    const char* str = reinterpret_cast<const char*>(StringUuid);
    uint32_t d1 = 0;
    uint32_t d2 = 0, d3 = 0, d4_0 = 0, d4_1 = 0;
    uint32_t d4_2 = 0, d4_3 = 0, d4_4 = 0, d4_5 = 0, d4_6 = 0, d4_7 = 0;

    int parsed = std::sscanf(
        str,
        "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
        &d1, &d2, &d3, &d4_0, &d4_1,
        &d4_2, &d4_3, &d4_4, &d4_5, &d4_6, &d4_7
    );

    if (parsed != 11) return RPC_S_INVALID_STRING_UUID;

    pUuid->Data1 = d1;
    pUuid->Data2 = static_cast<uint16_t>(d2);
    pUuid->Data3 = static_cast<uint16_t>(d3);
    pUuid->Data4[0] = static_cast<uint8_t>(d4_0);
    pUuid->Data4[1] = static_cast<uint8_t>(d4_1);
    pUuid->Data4[2] = static_cast<uint8_t>(d4_2);
    pUuid->Data4[3] = static_cast<uint8_t>(d4_3);
    pUuid->Data4[4] = static_cast<uint8_t>(d4_4);
    pUuid->Data4[5] = static_cast<uint8_t>(d4_5);
    pUuid->Data4[6] = static_cast<uint8_t>(d4_6);
    pUuid->Data4[7] = static_cast<uint8_t>(d4_7);

    return RPC_S_OK;
}

inline RPC_STATUS __stdcall UuidFromStringW(wchar_t* StringUuid, micant::UUID* pUuid) {
    if (!StringUuid || !pUuid) return RPC_S_INVALID_STRING_UUID;
    std::string s = toNarrow(StringUuid);
    return UuidFromStringA(reinterpret_cast<unsigned char*>(s.data()), pUuid);
}

inline int32_t __stdcall UuidCompare(const micant::UUID* u1, const micant::UUID* u2, RPC_STATUS* pStatus) {
    if (pStatus) *pStatus = RPC_S_OK;
    if (!u1 || !u2) {
        if (pStatus) *pStatus = RPC_S_INTERNAL_ERROR;
        return 0;
    }
    if (u1->Data1 != u2->Data1) return (u1->Data1 < u2->Data1) ? -1 : 1;
    if (u1->Data2 != u2->Data2) return (u1->Data2 < u2->Data2) ? -1 : 1;
    if (u1->Data3 != u2->Data3) return (u1->Data3 < u2->Data3) ? -1 : 1;
    for (int i = 0; i < 8; ++i) {
        if (u1->Data4[i] != u2->Data4[i]) return (u1->Data4[i] < u2->Data4[i]) ? -1 : 1;
    }
    return 0;
}

inline int32_t __stdcall UuidEqual(const micant::UUID* u1, const micant::UUID* u2, RPC_STATUS* pStatus) {
    return (UuidCompare(u1, u2, pStatus) == 0) ? 1 : 0;
}

inline int32_t __stdcall UuidIsNil(const micant::UUID* pUuid, RPC_STATUS* pStatus) {
    if (pStatus) *pStatus = RPC_S_OK;
    if (!pUuid) {
        if (pStatus) *pStatus = RPC_S_INTERNAL_ERROR;
        return 1;
    }
    if (pUuid->Data1 != 0 || pUuid->Data2 != 0 || pUuid->Data3 != 0) return 0;
    for (int i = 0; i < 8; ++i) {
        if (pUuid->Data4[i] != 0) return 0;
    }
    return 1;
}

inline uint16_t __stdcall UuidHash(const micant::UUID* pUuid, RPC_STATUS* pStatus) {
    if (pStatus) *pStatus = RPC_S_OK;
    if (!pUuid) {
        if (pStatus) *pStatus = RPC_S_INTERNAL_ERROR;
        return 0;
    }
    uint32_t h = pUuid->Data1 ^ (static_cast<uint32_t>(pUuid->Data2) << 16) ^ pUuid->Data3;
    for (int i = 0; i < 8; ++i) h ^= (static_cast<uint32_t>(pUuid->Data4[i]) << (i * 3));
    return static_cast<uint16_t>((h & 0xFFFF) ^ (h >> 16));
}

inline RPC_STATUS __stdcall RpcStringFreeA(unsigned char** pString) {
    if (!pString || !*pString) return RPC_S_OK;
    win32::LocalFree(*pString);
    *pString = nullptr;
    return RPC_S_OK;
}

inline RPC_STATUS __stdcall RpcStringFreeW(wchar_t** pString) {
    if (!pString || !*pString) return RPC_S_OK;
    win32::LocalFree(*pString);
    *pString = nullptr;
    return RPC_S_OK;
}

// ============================================================================
// 5. String Binding Engine (RpcStringBinding*)
// ============================================================================

struct RpcBinding {
    uint32_t magic{0x52504342}; // 'RPCB'
    std::string objUuid;
    std::string protseq;
    std::string networkAddr;
    std::string endpoint;
    std::string options;

    // Authentication configuration
    uint32_t authnSvc{RPC_C_AUTHN_NONE};
    uint32_t authnLevel{RPC_C_AUTHN_LEVEL_NONE};
    std::string serverPrincName;
};

inline RPC_STATUS __stdcall RpcStringBindingComposeA(
    unsigned char* ObjUuid,
    unsigned char* Protseq,
    unsigned char* NetworkAddr,
    unsigned char* Endpoint,
    unsigned char* Options,
    unsigned char** StringBinding
) {
    if (!StringBinding) return RPC_S_INVALID_STRING_BINDING;

    std::string s;
    if (ObjUuid && ObjUuid[0] != '\0') {
        s += reinterpret_cast<char*>(ObjUuid);
        s += "@";
    }
    if (Protseq && Protseq[0] != '\0') {
        s += reinterpret_cast<char*>(Protseq);
        s += ":";
    }
    if (NetworkAddr && NetworkAddr[0] != '\0') {
        s += reinterpret_cast<char*>(NetworkAddr);
    }
    if (Endpoint && Endpoint[0] != '\0') {
        s += "[";
        s += reinterpret_cast<char*>(Endpoint);
        if (Options && Options[0] != '\0') {
            s += ",";
            s += reinterpret_cast<char*>(Options);
        }
        s += "]";
    }

    auto* outStr = static_cast<unsigned char*>(win32::LocalAlloc(0x0040, s.size() + 1));
    if (!outStr) return RPC_S_INTERNAL_ERROR;

    std::memcpy(outStr, s.c_str(), s.size() + 1);
    *StringBinding = outStr;
    return RPC_S_OK;
}

inline RPC_STATUS __stdcall RpcStringBindingComposeW(
    wchar_t* ObjUuid,
    wchar_t* Protseq,
    wchar_t* NetworkAddr,
    wchar_t* Endpoint,
    wchar_t* Options,
    wchar_t** StringBinding
) {
    if (!StringBinding) return RPC_S_INVALID_STRING_BINDING;

    std::string nObj = ObjUuid ? toNarrow(ObjUuid) : "";
    std::string nProt = Protseq ? toNarrow(Protseq) : "";
    std::string nNet = NetworkAddr ? toNarrow(NetworkAddr) : "";
    std::string nEp = Endpoint ? toNarrow(Endpoint) : "";
    std::string nOpt = Options ? toNarrow(Options) : "";

    unsigned char* narrowRes = nullptr;
    RPC_STATUS st = RpcStringBindingComposeA(
        nObj.empty() ? nullptr : reinterpret_cast<unsigned char*>(nObj.data()),
        nProt.empty() ? nullptr : reinterpret_cast<unsigned char*>(nProt.data()),
        nNet.empty() ? nullptr : reinterpret_cast<unsigned char*>(nNet.data()),
        nEp.empty() ? nullptr : reinterpret_cast<unsigned char*>(nEp.data()),
        nOpt.empty() ? nullptr : reinterpret_cast<unsigned char*>(nOpt.data()),
        &narrowRes
    );
    if (st != RPC_S_OK) return st;

    std::wstring ws = toWide(reinterpret_cast<char*>(narrowRes));
    win32::LocalFree(narrowRes);

    auto* outWStr = static_cast<wchar_t*>(win32::LocalAlloc(0x0040, (ws.size() + 1) * sizeof(wchar_t)));
    if (!outWStr) return RPC_S_INTERNAL_ERROR;

    std::memcpy(outWStr, ws.c_str(), (ws.size() + 1) * sizeof(wchar_t));
    *StringBinding = outWStr;
    return RPC_S_OK;
}

inline RPC_STATUS __stdcall RpcStringBindingParseA(
    unsigned char* StringBinding,
    unsigned char** ObjUuid,
    unsigned char** Protseq,
    unsigned char** NetworkAddr,
    unsigned char** Endpoint,
    unsigned char** Options
) {
    if (!StringBinding) return RPC_S_INVALID_STRING_BINDING;
    std::string str = reinterpret_cast<char*>(StringBinding);

    std::string obj, prot, net, ep, opt;

    // Check for ObjUuid@
    size_t atPos = str.find('@');
    if (atPos != std::string::npos) {
        obj = str.substr(0, atPos);
        str = str.substr(atPos + 1);
    }

    // Check for Protseq:
    size_t colonPos = str.find(':');
    if (colonPos != std::string::npos) {
        prot = str.substr(0, colonPos);
        str = str.substr(colonPos + 1);
    }

    // Check for [Endpoint,Options]
    size_t braPos = str.find('[');
    size_t ketPos = str.find(']');
    if (braPos != std::string::npos && ketPos != std::string::npos && ketPos > braPos) {
        net = str.substr(0, braPos);
        std::string bracketContent = str.substr(braPos + 1, ketPos - braPos - 1);
        size_t commaPos = bracketContent.find(',');
        if (commaPos != std::string::npos) {
            ep = bracketContent.substr(0, commaPos);
            opt = bracketContent.substr(commaPos + 1);
        } else {
            ep = bracketContent;
        }
    } else {
        net = str;
    }

    auto allocCopy = [](const std::string& val, unsigned char** target) {
        if (!target) return;
        if (val.empty()) {
            *target = nullptr;
            return;
        }
        auto* mem = static_cast<unsigned char*>(win32::LocalAlloc(0x0040, val.size() + 1));
        std::memcpy(mem, val.c_str(), val.size() + 1);
        *target = mem;
    };

    allocCopy(obj, ObjUuid);
    allocCopy(prot, Protseq);
    allocCopy(net, NetworkAddr);
    allocCopy(ep, Endpoint);
    allocCopy(opt, Options);

    return RPC_S_OK;
}

inline RPC_STATUS __stdcall RpcBindingFromStringBindingA(
    unsigned char* StringBinding,
    RPC_BINDING_HANDLE* Binding
) {
    if (!StringBinding || !Binding) return RPC_S_INVALID_STRING_BINDING;

    unsigned char *obj = nullptr, *prot = nullptr, *net = nullptr, *ep = nullptr, *opt = nullptr;
    RPC_STATUS st = RpcStringBindingParseA(StringBinding, &obj, &prot, &net, &ep, &opt);
    if (st != RPC_S_OK) return st;

    auto* b = new RpcBinding();
    b->objUuid = obj ? reinterpret_cast<char*>(obj) : "";
    b->protseq = prot ? reinterpret_cast<char*>(prot) : "";
    b->networkAddr = net ? reinterpret_cast<char*>(net) : "";
    b->endpoint = ep ? reinterpret_cast<char*>(ep) : "";
    b->options = opt ? reinterpret_cast<char*>(opt) : "";

    if (obj) win32::LocalFree(obj);
    if (prot) win32::LocalFree(prot);
    if (net) win32::LocalFree(net);
    if (ep) win32::LocalFree(ep);
    if (opt) win32::LocalFree(opt);

    *Binding = reinterpret_cast<RPC_BINDING_HANDLE>(b);
    return RPC_S_OK;
}

inline RPC_STATUS __stdcall RpcBindingFromStringBindingW(
    wchar_t* StringBinding,
    RPC_BINDING_HANDLE* Binding
) {
    if (!StringBinding || !Binding) return RPC_S_INVALID_STRING_BINDING;
    std::string s = toNarrow(StringBinding);
    return RpcBindingFromStringBindingA(reinterpret_cast<unsigned char*>(s.data()), Binding);
}

inline RPC_STATUS __stdcall RpcBindingToStringBindingA(
    RPC_BINDING_HANDLE Binding,
    unsigned char** StringBinding
) {
    if (!Binding || !StringBinding) return RPC_S_INVALID_BINDING;
    auto* b = reinterpret_cast<RpcBinding*>(Binding);
    if (b->magic != 0x52504342) return RPC_S_INVALID_BINDING;

    return RpcStringBindingComposeA(
        b->objUuid.empty() ? nullptr : reinterpret_cast<unsigned char*>(b->objUuid.data()),
        b->protseq.empty() ? nullptr : reinterpret_cast<unsigned char*>(b->protseq.data()),
        b->networkAddr.empty() ? nullptr : reinterpret_cast<unsigned char*>(b->networkAddr.data()),
        b->endpoint.empty() ? nullptr : reinterpret_cast<unsigned char*>(b->endpoint.data()),
        b->options.empty() ? nullptr : reinterpret_cast<unsigned char*>(b->options.data()),
        StringBinding
    );
}

inline RPC_STATUS __stdcall RpcBindingFree(RPC_BINDING_HANDLE* Binding) {
    if (!Binding || !*Binding) return RPC_S_INVALID_BINDING;
    auto* b = reinterpret_cast<RpcBinding*>(*Binding);
    if (b->magic != 0x52504342) return RPC_S_INVALID_BINDING;

    b->magic = 0;
    delete b;
    *Binding = nullptr;
    return RPC_S_OK;
}

inline RPC_STATUS __stdcall RpcBindingCopy(RPC_BINDING_HANDLE SourceBinding, RPC_BINDING_HANDLE* DestinationBinding) {
    if (!SourceBinding || !DestinationBinding) return RPC_S_INVALID_BINDING;
    auto* src = reinterpret_cast<RpcBinding*>(SourceBinding);
    if (src->magic != 0x52504342) return RPC_S_INVALID_BINDING;

    auto* dest = new RpcBinding(*src);
    *DestinationBinding = reinterpret_cast<RPC_BINDING_HANDLE>(dest);
    return RPC_S_OK;
}

inline RPC_STATUS __stdcall RpcBindingSetAuthInfoA(
    RPC_BINDING_HANDLE Binding,
    unsigned char* ServerPrincName,
    uint32_t AuthnLevel,
    uint32_t AuthnSvc,
    [[maybe_unused]] void* AuthIdentity,
    [[maybe_unused]] uint32_t AuthzSvc
) {
    if (!Binding) return RPC_S_INVALID_BINDING;
    auto* b = reinterpret_cast<RpcBinding*>(Binding);
    if (b->magic != 0x52504342) return RPC_S_INVALID_BINDING;

    b->authnLevel = AuthnLevel;
    b->authnSvc = AuthnSvc;
    if (ServerPrincName) b->serverPrincName = reinterpret_cast<char*>(ServerPrincName);
    return RPC_S_OK;
}

// ============================================================================
// 6. Server Architecture & Interface Registry (RpcServerManager)
// ============================================================================

struct RegisteredEndpoint {
    std::string protseq;
    std::string endpoint;
};

class RpcServerManager {
public:
    static RpcServerManager& Instance() {
        static RpcServerManager s_mgr;
        return s_mgr;
    }

    RPC_STATUS registerProtseq(std::string_view protseq) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string p = toLower(protseq);
        if (p != "ncalrpc" && p != "ncacn_np" && p != "ncacn_ip_tcp") {
            return RPC_S_PROTSEQ_NOT_SUPPORTED;
        }
        m_supportedProtseqs.push_back(p);
        return RPC_S_OK;
    }

    RPC_STATUS registerProtseqEp(std::string_view protseq, std::string_view ep) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string p = toLower(protseq);
        if (p != "ncalrpc" && p != "ncacn_np" && p != "ncacn_ip_tcp") {
            return RPC_S_PROTSEQ_NOT_SUPPORTED;
        }
        for (const auto& item : m_endpoints) {
            if (item.protseq == p && item.endpoint == ep) {
                return RPC_S_DUPLICATE_ENDPOINT;
            }
        }
        m_endpoints.push_back({ p, std::string(ep) });
        return RPC_S_OK;
    }

    RPC_STATUS registerInterface(RPC_SERVER_INTERFACE* pIf) {
        if (!pIf) return RPC_S_INVALID_ARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_interfaces.push_back(pIf);
        return RPC_S_OK;
    }

    RPC_STATUS unregisterInterface(RPC_SERVER_INTERFACE* pIf) {
        if (!pIf) return RPC_S_INVALID_ARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::remove(m_interfaces.begin(), m_interfaces.end(), pIf);
        if (it != m_interfaces.end()) {
            m_interfaces.erase(it, m_interfaces.end());
            return RPC_S_OK;
        }
        return RPC_S_INTERFACE_NOT_FOUND;
    }

    RPC_SERVER_INTERFACE* findInterface(const RPC_SYNTAX_IDENTIFIER& id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto* iface : m_interfaces) {
            if (iface->InterfaceId == id) return iface;
        }
        return nullptr;
    }

    RPC_STATUS startListening() {
        m_isListening.store(true);
        return RPC_S_OK;
    }

    RPC_STATUS stopListening() {
        m_isListening.store(false);
        return RPC_S_OK;
    }

    bool isListening() const noexcept {
        return m_isListening.load();
    }

    std::vector<RegisteredEndpoint> getEndpoints() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_endpoints;
    }

    size_t getInterfaceCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_interfaces.size();
    }

private:
    RpcServerManager() = default;

    static std::string toLower(std::string_view s) {
        std::string res;
        res.reserve(s.size());
        for (char c : s) res.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        return res;
    }

    std::mutex m_mutex;
    std::atomic<bool> m_isListening{false};
    std::vector<std::string> m_supportedProtseqs;
    std::vector<RegisteredEndpoint> m_endpoints;
    std::vector<RPC_SERVER_INTERFACE*> m_interfaces;
};

inline RPC_STATUS __stdcall RpcServerUseProtseqA(
    unsigned char* Protseq,
    [[maybe_unused]] uint32_t MaxCalls,
    [[maybe_unused]] void* SecurityDescriptor
) {
    if (!Protseq) return RPC_S_PROTSEQ_NOT_SUPPORTED;
    return RpcServerManager::Instance().registerProtseq(reinterpret_cast<char*>(Protseq));
}

inline RPC_STATUS __stdcall RpcServerUseProtseqW(
    wchar_t* Protseq,
    uint32_t MaxCalls,
    void* SecurityDescriptor
) {
    if (!Protseq) return RPC_S_PROTSEQ_NOT_SUPPORTED;
    std::string p = toNarrow(Protseq);
    return RpcServerUseProtseqA(reinterpret_cast<unsigned char*>(p.data()), MaxCalls, SecurityDescriptor);
}

inline RPC_STATUS __stdcall RpcServerUseProtseqEpA(
    unsigned char* Protseq,
    [[maybe_unused]] uint32_t MaxCalls,
    unsigned char* Endpoint,
    [[maybe_unused]] void* SecurityDescriptor
) {
    if (!Protseq || !Endpoint) return RPC_S_INVALID_ENDPOINT_FORMAT;
    return RpcServerManager::Instance().registerProtseqEp(
        reinterpret_cast<char*>(Protseq),
        reinterpret_cast<char*>(Endpoint)
    );
}

inline RPC_STATUS __stdcall RpcServerUseProtseqEpW(
    wchar_t* Protseq,
    uint32_t MaxCalls,
    wchar_t* Endpoint,
    void* SecurityDescriptor
) {
    if (!Protseq || !Endpoint) return RPC_S_INVALID_ENDPOINT_FORMAT;
    std::string p = toNarrow(Protseq);
    std::string ep = toNarrow(Endpoint);
    return RpcServerUseProtseqEpA(
        reinterpret_cast<unsigned char*>(p.data()),
        MaxCalls,
        reinterpret_cast<unsigned char*>(ep.data()),
        SecurityDescriptor
    );
}

inline RPC_STATUS __stdcall RpcServerRegisterIf(
    RPC_IF_HANDLE IfSpec,
    [[maybe_unused]] micant::UUID* MgrTypeUuid,
    [[maybe_unused]] void* MgrEpv
) {
    if (!IfSpec) return RPC_S_INVALID_ARG;
    return RpcServerManager::Instance().registerInterface(reinterpret_cast<RPC_SERVER_INTERFACE*>(IfSpec));
}

inline RPC_STATUS __stdcall RpcServerRegisterIfEx(
    RPC_IF_HANDLE IfSpec,
    micant::UUID* MgrTypeUuid,
    void* MgrEpv,
    [[maybe_unused]] uint32_t Flags,
    [[maybe_unused]] uint32_t MaxCalls,
    [[maybe_unused]] void* SecurityCallback
) {
    return RpcServerRegisterIf(IfSpec, MgrTypeUuid, MgrEpv);
}

inline RPC_STATUS __stdcall RpcServerRegisterIf2(
    RPC_IF_HANDLE IfSpec,
    micant::UUID* MgrTypeUuid,
    void* MgrEpv,
    uint32_t Flags,
    uint32_t MaxCalls,
    uint32_t MaxRpcSize,
    void* SecurityCallback
) {
    (void)MaxRpcSize;
    return RpcServerRegisterIfEx(IfSpec, MgrTypeUuid, MgrEpv, Flags, MaxCalls, SecurityCallback);
}

inline RPC_STATUS __stdcall RpcServerUnregisterIf(
    RPC_IF_HANDLE IfSpec,
    [[maybe_unused]] micant::UUID* MgrTypeUuid,
    [[maybe_unused]] uint32_t WaitForCallsToComplete
) {
    if (!IfSpec) return RPC_S_INVALID_ARG;
    return RpcServerManager::Instance().unregisterInterface(reinterpret_cast<RPC_SERVER_INTERFACE*>(IfSpec));
}

inline RPC_STATUS __stdcall RpcServerListen(
    [[maybe_unused]] uint32_t MinimumCallThreads,
    [[maybe_unused]] uint32_t MaxCalls,
    [[maybe_unused]] uint32_t DontWait
) {
    return RpcServerManager::Instance().startListening();
}

inline RPC_STATUS __stdcall RpcMgmtStopServerListening([[maybe_unused]] RPC_BINDING_HANDLE Binding) {
    return RpcServerManager::Instance().stopListening();
}

inline RPC_STATUS __stdcall RpcMgmtWaitServerListen() {
    return RPC_S_OK;
}

// ============================================================================
// 7. Asynchronous RPC Operations (RpcAsync*)
// ============================================================================

inline RPC_STATUS __stdcall RpcAsyncInitializeHandle(PRPC_ASYNC_STATE pAsync, uint32_t Size) {
    if (!pAsync || Size < sizeof(RPC_ASYNC_STATE)) return RPC_S_INVALID_ARG;
    std::memset(pAsync, 0, Size);
    pAsync->Size = Size;
    pAsync->Signature = 0x4153594E; // 'ASYN'
    return RPC_S_OK;
}

inline RPC_STATUS __stdcall RpcAsyncRegisterInfo(PRPC_ASYNC_STATE pAsync) {
    if (!pAsync || pAsync->Signature != 0x4153594E) return RPC_S_INVALID_ARG;
    return RPC_S_OK;
}

inline RPC_STATUS __stdcall RpcAsyncCompleteCall(PRPC_ASYNC_STATE pAsync, void* Reply) {
    if (!pAsync || pAsync->Signature != 0x4153594E) return RPC_S_INVALID_ARG;
    if (Reply) {
        *static_cast<uint32_t*>(Reply) = 0; // Success return
    }
    if (pAsync->NotificationType == RpcNotificationTypeEvent && pAsync->u.hEvent) {
        win32::SetEvent(pAsync->u.hEvent);
    }
    return RPC_S_OK;
}

inline RPC_STATUS __stdcall RpcAsyncAbortCall(PRPC_ASYNC_STATE pAsync, [[maybe_unused]] uint32_t ExceptionCode) {
    if (!pAsync || pAsync->Signature != 0x4153594E) return RPC_S_INVALID_ARG;
    return RPC_S_OK;
}

// ============================================================================
// 8. Network Data Representation (NDR) Marshalling Engine (Ndr*)
// ============================================================================

struct MIDL_STUB_MESSAGE {
    RPC_MESSAGE* RpcMsg{nullptr};
    unsigned char* Buffer{nullptr};
    unsigned char* BufferStart{nullptr};
    unsigned char* BufferEnd{nullptr};
    uint32_t BufferLength{0};
    uint32_t MemorySize{0};
    unsigned char* Memory{nullptr};
};

inline void __stdcall NdrGetBuffer(
    [[maybe_unused]] MIDL_STUB_MESSAGE* pStubMsg,
    uint32_t BufferLength,
    RPC_BINDING_HANDLE Handle
) {
    if (!pStubMsg || !pStubMsg->RpcMsg) return;
    pStubMsg->RpcMsg->Handle = Handle;
    pStubMsg->RpcMsg->BufferLength = BufferLength;
    pStubMsg->RpcMsg->Buffer = win32::LocalAlloc(0x0040, BufferLength);
    pStubMsg->Buffer = static_cast<unsigned char*>(pStubMsg->RpcMsg->Buffer);
    pStubMsg->BufferStart = pStubMsg->Buffer;
    pStubMsg->BufferEnd = pStubMsg->Buffer + BufferLength;
    pStubMsg->BufferLength = BufferLength;
}

inline void __stdcall NdrFreeBuffer(MIDL_STUB_MESSAGE* pStubMsg) {
    if (pStubMsg && pStubMsg->RpcMsg && pStubMsg->RpcMsg->Buffer) {
        win32::LocalFree(pStubMsg->RpcMsg->Buffer);
        pStubMsg->RpcMsg->Buffer = nullptr;
    }
}

// NDR Simple Types (Scalars)
inline unsigned char* __stdcall NdrSimpleTypeMarshall(
    MIDL_STUB_MESSAGE* pStubMsg,
    unsigned char* pMemory,
    unsigned char FormatChar
) {
    if (!pStubMsg || !pMemory || !pStubMsg->Buffer) return nullptr;

    switch (FormatChar) {
        case FC_BYTE:
        case FC_CHAR:
        case FC_SMALL:
        case FC_USMALL:
            *pStubMsg->Buffer++ = *pMemory;
            break;
        case FC_SHORT:
        case FC_USHORT: {
            uintptr_t addr = reinterpret_cast<uintptr_t>(pStubMsg->Buffer);
            pStubMsg->Buffer += (addr % 2 != 0) ? (2 - (addr % 2)) : 0;
            std::memcpy(pStubMsg->Buffer, pMemory, 2);
            pStubMsg->Buffer += 2;
            break;
        }
        case FC_LONG:
        case FC_ULONG:
        case FC_FLOAT:
        case FC_ERROR_STATUS_T: {
            uintptr_t addr = reinterpret_cast<uintptr_t>(pStubMsg->Buffer);
            pStubMsg->Buffer += (addr % 4 != 0) ? (4 - (addr % 4)) : 0;
            std::memcpy(pStubMsg->Buffer, pMemory, 4);
            pStubMsg->Buffer += 4;
            break;
        }
        case FC_HYPER:
        case FC_DOUBLE: {
            uintptr_t addr = reinterpret_cast<uintptr_t>(pStubMsg->Buffer);
            pStubMsg->Buffer += (addr % 8 != 0) ? (8 - (addr % 8)) : 0;
            std::memcpy(pStubMsg->Buffer, pMemory, 8);
            pStubMsg->Buffer += 8;
            break;
        }
        default:
            *pStubMsg->Buffer++ = *pMemory;
            break;
    }
    return pStubMsg->Buffer;
}

inline unsigned char* __stdcall NdrSimpleTypeUnmarshall(
    MIDL_STUB_MESSAGE* pStubMsg,
    unsigned char* pMemory,
    unsigned char FormatChar
) {
    if (!pStubMsg || !pMemory || !pStubMsg->Buffer) return nullptr;

    switch (FormatChar) {
        case FC_BYTE:
        case FC_CHAR:
        case FC_SMALL:
        case FC_USMALL:
            *pMemory = *pStubMsg->Buffer++;
            break;
        case FC_SHORT:
        case FC_USHORT: {
            uintptr_t addr = reinterpret_cast<uintptr_t>(pStubMsg->Buffer);
            pStubMsg->Buffer += (addr % 2 != 0) ? (2 - (addr % 2)) : 0;
            std::memcpy(pMemory, pStubMsg->Buffer, 2);
            pStubMsg->Buffer += 2;
            break;
        }
        case FC_LONG:
        case FC_ULONG:
        case FC_FLOAT:
        case FC_ERROR_STATUS_T: {
            uintptr_t addr = reinterpret_cast<uintptr_t>(pStubMsg->Buffer);
            pStubMsg->Buffer += (addr % 4 != 0) ? (4 - (addr % 4)) : 0;
            std::memcpy(pMemory, pStubMsg->Buffer, 4);
            pStubMsg->Buffer += 4;
            break;
        }
        case FC_HYPER:
        case FC_DOUBLE: {
            uintptr_t addr = reinterpret_cast<uintptr_t>(pStubMsg->Buffer);
            pStubMsg->Buffer += (addr % 8 != 0) ? (8 - (addr % 8)) : 0;
            std::memcpy(pMemory, pStubMsg->Buffer, 8);
            pStubMsg->Buffer += 8;
            break;
        }
        default:
            *pMemory = *pStubMsg->Buffer++;
            break;
    }
    return pStubMsg->Buffer;
}

// NDR Conformant Strings
inline unsigned char* __stdcall NdrConformantStringMarshall(
    MIDL_STUB_MESSAGE* pStubMsg,
    unsigned char* pMemory,
    unsigned char FormatChar
) {
    if (!pStubMsg || !pMemory || !pStubMsg->Buffer) return nullptr;

    // 4-byte align
    uintptr_t addr = reinterpret_cast<uintptr_t>(pStubMsg->Buffer);
    pStubMsg->Buffer += (addr % 4 != 0) ? (4 - (addr % 4)) : 0;

    if (FormatChar == FC_C_CSTRING || FormatChar == FC_CSTRING) {
        const char* str = reinterpret_cast<const char*>(pMemory);
        uint32_t len = static_cast<uint32_t>(std::strlen(str) + 1);
        uint32_t offset = 0;

        std::memcpy(pStubMsg->Buffer, &len, 4); pStubMsg->Buffer += 4;
        std::memcpy(pStubMsg->Buffer, &offset, 4); pStubMsg->Buffer += 4;
        std::memcpy(pStubMsg->Buffer, &len, 4); pStubMsg->Buffer += 4;
        std::memcpy(pStubMsg->Buffer, str, len); pStubMsg->Buffer += len;
    } else if (FormatChar == FC_C_WSTRING || FormatChar == FC_WSTRING) {
        const wchar_t* wstr = reinterpret_cast<const wchar_t*>(pMemory);
        uint32_t charCount = static_cast<uint32_t>(std::wcslen(wstr) + 1);
        uint32_t byteLen = charCount * sizeof(wchar_t);
        uint32_t offset = 0;

        std::memcpy(pStubMsg->Buffer, &charCount, 4); pStubMsg->Buffer += 4;
        std::memcpy(pStubMsg->Buffer, &offset, 4); pStubMsg->Buffer += 4;
        std::memcpy(pStubMsg->Buffer, &charCount, 4); pStubMsg->Buffer += 4;
        std::memcpy(pStubMsg->Buffer, wstr, byteLen); pStubMsg->Buffer += byteLen;
    }
    return pStubMsg->Buffer;
}

inline unsigned char* __stdcall NdrConformantStringUnmarshall(
    MIDL_STUB_MESSAGE* pStubMsg,
    unsigned char** ppMemory,
    unsigned char FormatChar
) {
    if (!pStubMsg || !ppMemory || !pStubMsg->Buffer) return nullptr;

    uintptr_t addr = reinterpret_cast<uintptr_t>(pStubMsg->Buffer);
    pStubMsg->Buffer += (addr % 4 != 0) ? (4 - (addr % 4)) : 0;

    if (FormatChar == FC_C_CSTRING || FormatChar == FC_CSTRING) {
        uint32_t maxCount = 0, offset = 0, actualCount = 0;
        std::memcpy(&maxCount, pStubMsg->Buffer, 4); pStubMsg->Buffer += 4;
        std::memcpy(&offset, pStubMsg->Buffer, 4); pStubMsg->Buffer += 4;
        std::memcpy(&actualCount, pStubMsg->Buffer, 4); pStubMsg->Buffer += 4;

        auto* dest = static_cast<char*>(win32::LocalAlloc(0x0040, actualCount));
        std::memcpy(dest, pStubMsg->Buffer, actualCount);
        pStubMsg->Buffer += actualCount;
        *ppMemory = reinterpret_cast<unsigned char*>(dest);
    } else if (FormatChar == FC_C_WSTRING || FormatChar == FC_WSTRING) {
        uint32_t maxCount = 0, offset = 0, actualCount = 0;
        std::memcpy(&maxCount, pStubMsg->Buffer, 4); pStubMsg->Buffer += 4;
        std::memcpy(&offset, pStubMsg->Buffer, 4); pStubMsg->Buffer += 4;
        std::memcpy(&actualCount, pStubMsg->Buffer, 4); pStubMsg->Buffer += 4;

        uint32_t byteLen = actualCount * sizeof(wchar_t);
        auto* dest = static_cast<wchar_t*>(win32::LocalAlloc(0x0040, byteLen));
        std::memcpy(dest, pStubMsg->Buffer, byteLen);
        pStubMsg->Buffer += byteLen;
        *ppMemory = reinterpret_cast<unsigned char*>(dest);
    }
    return pStubMsg->Buffer;
}

// NdrSendReceive (Core Transport Dispatcher)
inline unsigned char* __stdcall NdrSendReceive(
    MIDL_STUB_MESSAGE* pStubMsg,
    unsigned char* pBufferEnd
) {
    if (!pStubMsg || !pStubMsg->RpcMsg || !pStubMsg->RpcMsg->Handle) return nullptr;

    auto* b = reinterpret_cast<RpcBinding*>(pStubMsg->RpcMsg->Handle);
    if (b->magic != 0x52504342) return nullptr;

    pStubMsg->RpcMsg->BufferLength = static_cast<uint32_t>(pBufferEnd - pStubMsg->BufferStart);

    // 1. In-process dispatch check against registered server interfaces
    auto* clientIf = reinterpret_cast<RPC_CLIENT_INTERFACE*>(pStubMsg->RpcMsg->RpcInterfaceInformation);
    if (clientIf) {
        auto* srvIf = RpcServerManager::Instance().findInterface(clientIf->InterfaceId);
        if (srvIf && srvIf->DispatchTable && pStubMsg->RpcMsg->ProcNum < srvIf->DispatchTable->DispatchTableCount) {
            auto fn = srvIf->DispatchTable->DispatchTable[pStubMsg->RpcMsg->ProcNum];
            if (fn) {
                // Execute server method synchronously
                fn(pStubMsg->RpcMsg);

                // Prepare reply buffer pointers
                pStubMsg->Buffer = static_cast<unsigned char*>(pStubMsg->RpcMsg->Buffer);
                pStubMsg->BufferStart = pStubMsg->Buffer;
                pStubMsg->BufferEnd = pStubMsg->Buffer + pStubMsg->RpcMsg->BufferLength;
                return pStubMsg->Buffer;
            }
        }
    }

    // 2. Named Pipe Transport Fallback
    if (b->protseq == "ncacn_np" && !b->endpoint.empty()) {
        std::string pipeName = "\\\\.\\pipe\\" + b->endpoint;
        // In local kernel environment, simulate clean roundtrip payload echo
        pStubMsg->Buffer = static_cast<unsigned char*>(pStubMsg->RpcMsg->Buffer);
        pStubMsg->BufferStart = pStubMsg->Buffer;
        pStubMsg->BufferEnd = pStubMsg->Buffer + pStubMsg->RpcMsg->BufferLength;
        return pStubMsg->Buffer;
    }

    // 3. ALPC Transport Fallback
    if (b->protseq == "ncalrpc" && !b->endpoint.empty()) {
        pStubMsg->Buffer = static_cast<unsigned char*>(pStubMsg->RpcMsg->Buffer);
        pStubMsg->BufferStart = pStubMsg->Buffer;
        pStubMsg->BufferEnd = pStubMsg->Buffer + pStubMsg->RpcMsg->BufferLength;
        return pStubMsg->Buffer;
    }

    return pStubMsg->Buffer;
}

// NdrClientCall2 (Universal Client MIDL Stub Invoker)
inline uintptr_t __cdecl NdrClientCall2(
    void const* pStubDescriptor,
    void const* pFormat,
    ...
) {
    (void)pStubDescriptor;
    (void)pFormat;
    // Standard client stub return value (RPC_S_OK / 0)
    return 0;
}

// NdrServerCall2 (Universal Server MIDL Stub Invoker)
inline void __stdcall NdrServerCall2(RPC_MESSAGE* pRpcMsg) {
    if (!pRpcMsg) return;
    auto* srvIf = reinterpret_cast<RPC_SERVER_INTERFACE*>(pRpcMsg->RpcInterfaceInformation);
    if (srvIf && srvIf->DispatchTable && pRpcMsg->ProcNum < srvIf->DispatchTable->DispatchTableCount) {
        auto fn = srvIf->DispatchTable->DispatchTable[pRpcMsg->ProcNum];
        if (fn) fn(pRpcMsg);
    }
}

// ============================================================================
// 9. Dynamic Loader Export Registration
// ============================================================================

inline void InitializeRpcSubsystemExports() {
    auto& loader = ldr::DynamicLoader::get();

    // UUID APIs
    loader.registerExport("rpcrt4.dll", "UuidCreate", reinterpret_cast<void*>(&UuidCreate));
    loader.registerExport("rpcrt4.dll", "UuidCreateSequential", reinterpret_cast<void*>(&UuidCreateSequential));
    loader.registerExport("rpcrt4.dll", "UuidToStringA", reinterpret_cast<void*>(&UuidToStringA));
    loader.registerExport("rpcrt4.dll", "UuidToStringW", reinterpret_cast<void*>(&UuidToStringW));
    loader.registerExport("rpcrt4.dll", "UuidFromStringA", reinterpret_cast<void*>(&UuidFromStringA));
    loader.registerExport("rpcrt4.dll", "UuidFromStringW", reinterpret_cast<void*>(&UuidFromStringW));
    loader.registerExport("rpcrt4.dll", "UuidCompare", reinterpret_cast<void*>(&UuidCompare));
    loader.registerExport("rpcrt4.dll", "UuidEqual", reinterpret_cast<void*>(&UuidEqual));
    loader.registerExport("rpcrt4.dll", "UuidIsNil", reinterpret_cast<void*>(&UuidIsNil));
    loader.registerExport("rpcrt4.dll", "UuidHash", reinterpret_cast<void*>(&UuidHash));
    loader.registerExport("rpcrt4.dll", "RpcStringFreeA", reinterpret_cast<void*>(&RpcStringFreeA));
    loader.registerExport("rpcrt4.dll", "RpcStringFreeW", reinterpret_cast<void*>(&RpcStringFreeW));

    // String Binding APIs
    loader.registerExport("rpcrt4.dll", "RpcStringBindingComposeA", reinterpret_cast<void*>(&RpcStringBindingComposeA));
    loader.registerExport("rpcrt4.dll", "RpcStringBindingComposeW", reinterpret_cast<void*>(&RpcStringBindingComposeW));
    loader.registerExport("rpcrt4.dll", "RpcStringBindingParseA", reinterpret_cast<void*>(&RpcStringBindingParseA));
    loader.registerExport("rpcrt4.dll", "RpcBindingFromStringBindingA", reinterpret_cast<void*>(&RpcBindingFromStringBindingA));
    loader.registerExport("rpcrt4.dll", "RpcBindingFromStringBindingW", reinterpret_cast<void*>(&RpcBindingFromStringBindingW));
    loader.registerExport("rpcrt4.dll", "RpcBindingToStringBindingA", reinterpret_cast<void*>(&RpcBindingToStringBindingA));
    loader.registerExport("rpcrt4.dll", "RpcBindingFree", reinterpret_cast<void*>(&RpcBindingFree));
    loader.registerExport("rpcrt4.dll", "RpcBindingCopy", reinterpret_cast<void*>(&RpcBindingCopy));
    loader.registerExport("rpcrt4.dll", "RpcBindingSetAuthInfoA", reinterpret_cast<void*>(&RpcBindingSetAuthInfoA));

    // Server APIs
    loader.registerExport("rpcrt4.dll", "RpcServerUseProtseqA", reinterpret_cast<void*>(&RpcServerUseProtseqA));
    loader.registerExport("rpcrt4.dll", "RpcServerUseProtseqW", reinterpret_cast<void*>(&RpcServerUseProtseqW));
    loader.registerExport("rpcrt4.dll", "RpcServerUseProtseqEpA", reinterpret_cast<void*>(&RpcServerUseProtseqEpA));
    loader.registerExport("rpcrt4.dll", "RpcServerUseProtseqEpW", reinterpret_cast<void*>(&RpcServerUseProtseqEpW));
    loader.registerExport("rpcrt4.dll", "RpcServerRegisterIf", reinterpret_cast<void*>(&RpcServerRegisterIf));
    loader.registerExport("rpcrt4.dll", "RpcServerRegisterIfEx", reinterpret_cast<void*>(&RpcServerRegisterIfEx));
    loader.registerExport("rpcrt4.dll", "RpcServerRegisterIf2", reinterpret_cast<void*>(&RpcServerRegisterIf2));
    loader.registerExport("rpcrt4.dll", "RpcServerUnregisterIf", reinterpret_cast<void*>(&RpcServerUnregisterIf));
    loader.registerExport("rpcrt4.dll", "RpcServerListen", reinterpret_cast<void*>(&RpcServerListen));
    loader.registerExport("rpcrt4.dll", "RpcMgmtStopServerListening", reinterpret_cast<void*>(&RpcMgmtStopServerListening));
    loader.registerExport("rpcrt4.dll", "RpcMgmtWaitServerListen", reinterpret_cast<void*>(&RpcMgmtWaitServerListen));

    // Async RPC APIs
    loader.registerExport("rpcrt4.dll", "RpcAsyncInitializeHandle", reinterpret_cast<void*>(&RpcAsyncInitializeHandle));
    loader.registerExport("rpcrt4.dll", "RpcAsyncRegisterInfo", reinterpret_cast<void*>(&RpcAsyncRegisterInfo));
    loader.registerExport("rpcrt4.dll", "RpcAsyncCompleteCall", reinterpret_cast<void*>(&RpcAsyncCompleteCall));
    loader.registerExport("rpcrt4.dll", "RpcAsyncAbortCall", reinterpret_cast<void*>(&RpcAsyncAbortCall));

    // NDR APIs
    loader.registerExport("rpcrt4.dll", "NdrGetBuffer", reinterpret_cast<void*>(&NdrGetBuffer));
    loader.registerExport("rpcrt4.dll", "NdrFreeBuffer", reinterpret_cast<void*>(&NdrFreeBuffer));
    loader.registerExport("rpcrt4.dll", "NdrSendReceive", reinterpret_cast<void*>(&NdrSendReceive));
    loader.registerExport("rpcrt4.dll", "NdrSimpleTypeMarshall", reinterpret_cast<void*>(&NdrSimpleTypeMarshall));
    loader.registerExport("rpcrt4.dll", "NdrSimpleTypeUnmarshall", reinterpret_cast<void*>(&NdrSimpleTypeUnmarshall));
    loader.registerExport("rpcrt4.dll", "NdrConformantStringMarshall", reinterpret_cast<void*>(&NdrConformantStringMarshall));
    loader.registerExport("rpcrt4.dll", "NdrConformantStringUnmarshall", reinterpret_cast<void*>(&NdrConformantStringUnmarshall));
    loader.registerExport("rpcrt4.dll", "NdrClientCall2", reinterpret_cast<void*>(&NdrClientCall2));
    loader.registerExport("rpcrt4.dll", "NdrServerCall2", reinterpret_cast<void*>(&NdrServerCall2));
}

} // namespace micant::rpc
