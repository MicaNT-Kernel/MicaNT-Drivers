#pragma once

/**
 * @file winscard.hpp
 * @brief Clean-room Windows Smart Card & PC/SC Subsystem (winscard.dll / scredir.dll).
 * 
 * Implements the Win32 Smart Card (PC/SC) API surface, resource manager (ScardSvr),
 * reader enumeration, card connection/disconnection, ISO 7816-4 APDU command/response
 * transmission (PIV / CAC / FIDO2 tokens), and status polling.
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

namespace micant::scard {

// ============================================================================
// 1. Win32 Smart Card Constants & Types (win32metadata)
// ============================================================================

using SCARDCONTEXT = uintptr_t;
using SCARDHANDLE  = uintptr_t;

// Scopes
inline constexpr uint32_t SCARD_SCOPE_USER       = 0;
inline constexpr uint32_t SCARD_SCOPE_TERMINAL   = 1;
inline constexpr uint32_t SCARD_SCOPE_SYSTEM     = 2;

// Share Modes
inline constexpr uint32_t SCARD_SHARE_EXCLUSIVE  = 1;
inline constexpr uint32_t SCARD_SHARE_SHARED     = 2;
inline constexpr uint32_t SCARD_SHARE_DIRECT     = 3;

// Protocols
inline constexpr uint32_t SCARD_PROTOCOL_UNDEFINED = 0x00000000;
inline constexpr uint32_t SCARD_PROTOCOL_T0        = 0x00000001;
inline constexpr uint32_t SCARD_PROTOCOL_T1        = 0x00000002;
inline constexpr uint32_t SCARD_PROTOCOL_RAW       = 0x00010000;
inline constexpr uint32_t SCARD_PROTOCOL_Tx        = (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1);

// Dispositions
inline constexpr uint32_t SCARD_LEAVE_CARD       = 0;
inline constexpr uint32_t SCARD_RESET_CARD       = 1;
inline constexpr uint32_t SCARD_UNPOWER_CARD     = 2;
inline constexpr uint32_t SCARD_EJECT_CARD       = 3;

// Reader States
inline constexpr uint32_t SCARD_STATE_UNAWARE     = 0x00000000;
inline constexpr uint32_t SCARD_STATE_IGNORE      = 0x00000001;
inline constexpr uint32_t SCARD_STATE_CHANGED     = 0x00000002;
inline constexpr uint32_t SCARD_STATE_UNKNOWN     = 0x00000004;
inline constexpr uint32_t SCARD_STATE_UNAVAILABLE = 0x00000008;
inline constexpr uint32_t SCARD_STATE_EMPTY       = 0x00000010;
inline constexpr uint32_t SCARD_STATE_PRESENT     = 0x00000020;
inline constexpr uint32_t SCARD_STATE_ATRMATCH    = 0x00000040;
inline constexpr uint32_t SCARD_STATE_EXCLUSIVE   = 0x00000080;
inline constexpr uint32_t SCARD_STATE_INUSE       = 0x00000100;
inline constexpr uint32_t SCARD_STATE_MUTE        = 0x00000200;
inline constexpr uint32_t SCARD_STATE_UNPOWERED   = 0x00000400;

// Smart Card Error Codes
inline constexpr int32_t SCARD_S_SUCCESS               = 0;
inline constexpr int32_t SCARD_F_INTERNAL_ERROR        = static_cast<int32_t>(0x80100001);
inline constexpr int32_t SCARD_E_CANCELLED             = static_cast<int32_t>(0x80100002);
inline constexpr int32_t SCARD_E_INVALID_HANDLE        = static_cast<int32_t>(0x80100003);
inline constexpr int32_t SCARD_E_INVALID_PARAMETER     = static_cast<int32_t>(0x80100004);
inline constexpr int32_t SCARD_E_NO_SMARTCARD          = static_cast<int32_t>(0x8010000C);
inline constexpr int32_t SCARD_E_PROTO_MISMATCH        = static_cast<int32_t>(0x8010000F);
inline constexpr int32_t SCARD_E_NOT_READY             = static_cast<int32_t>(0x80100010);
inline constexpr int32_t SCARD_E_INVALID_VALUE         = static_cast<int32_t>(0x80100011);
inline constexpr int32_t SCARD_E_READER_UNAVAILABLE    = static_cast<int32_t>(0x80100017);
inline constexpr int32_t SCARD_E_NO_SERVICE            = static_cast<int32_t>(0x8010001D);
inline constexpr int32_t SCARD_E_SERVICE_STOPPED       = static_cast<int32_t>(0x8010001E);
inline constexpr int32_t SCARD_E_NO_READERS_AVAILABLE  = static_cast<int32_t>(0x8010002E);
inline constexpr int32_t SCARD_E_CARD_UNSUPPORTED      = static_cast<int32_t>(0x80100065);
inline constexpr int32_t SCARD_W_UNRESPONSIVE_CARD     = static_cast<int32_t>(0x80100066);
inline constexpr int32_t SCARD_W_UNPOWERED_CARD        = static_cast<int32_t>(0x80100067);
inline constexpr int32_t SCARD_W_RESET_CARD            = static_cast<int32_t>(0x80100068);
inline constexpr int32_t SCARD_W_REMOVED_CARD          = static_cast<int32_t>(0x80100069);

// Standard Reader Groups
inline constexpr const wchar_t* SCARD_ALL_READERS     = L"SCard$AllReaders\0\0";
inline constexpr const wchar_t* SCARD_DEFAULT_READERS = L"SCard$DefaultReaders\0\0";

#pragma pack(push, 1)

struct SCARD_IO_REQUEST {
    uint32_t dwProtocol;
    uint32_t cbPciLength;
};

struct SCARD_READERSTATEW {
    const wchar_t* szReader;
    void*          pvUserData;
    uint32_t       dwCurrentState;
    uint32_t       dwEventState;
    uint32_t       cbAtr;
    uint8_t        rgbAtr[36];
};

struct SCARD_READERSTATEA {
    const char* szReader;
    void*       pvUserData;
    uint32_t    dwCurrentState;
    uint32_t    dwEventState;
    uint32_t    cbAtr;
    uint8_t     rgbAtr[36];
};

#pragma pack(pop)

// Pre-defined PCI Structures
inline const SCARD_IO_REQUEST g_rgSCardT0Pci  = { SCARD_PROTOCOL_T0,  sizeof(SCARD_IO_REQUEST) };
inline const SCARD_IO_REQUEST g_rgSCardT1Pci  = { SCARD_PROTOCOL_T1,  sizeof(SCARD_IO_REQUEST) };
inline const SCARD_IO_REQUEST g_rgSCardRawPci = { SCARD_PROTOCOL_RAW, sizeof(SCARD_IO_REQUEST) };

// ============================================================================
// 2. Sovereign Smart Card Virtual Reader & Token Engine
// ============================================================================

struct SmartCardSlot {
    std::wstring readerName;
    bool cardPresent{false};
    std::wstring cardName;
    std::vector<uint8_t> atr;
    uint32_t activeProtocol{SCARD_PROTOCOL_T1};
    uint32_t supportedProtocols{SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1};
    std::string pin{"123456"};
    int pinRemainingAttempts{3};
};

struct SmartCardConnection {
    SCARDHANDLE handle{0};
    SCARDCONTEXT context{0};
    std::wstring readerName;
    uint32_t shareMode{SCARD_SHARE_SHARED};
    uint32_t activeProtocol{SCARD_PROTOCOL_T1};
};

class SmartCardManager {
private:
    mutable std::mutex m_mutex;
    std::map<std::wstring, SmartCardSlot> m_readers;
    std::vector<SCARDCONTEXT> m_activeContexts;
    std::map<SCARDHANDLE, SmartCardConnection> m_connections;
    uintptr_t m_nextContextId{0x1000};
    uintptr_t m_nextHandleId{0x5000};
    bool m_serviceRunning{true};

    SmartCardManager() {
        initDefaultReaders();
        registerScmServices();
    }

    void initDefaultReaders() {
        // 1. Virtual PIV / CAC Security Token Reader
        {
            SmartCardSlot slot;
            slot.readerName = L"MicaNT Virtual PIV/CAC SmartCard Reader 0";
            slot.cardPresent = true;
            slot.cardName = L"MicaNT Sovereign PIV Security Token";
            // Standard PIV/CAC ATR: 3B 7D 96 00 00 80 31 80 65 B0 83 11 17 D6 83 00 90 00 (18 bytes)
            slot.atr = { 0x3B, 0x7D, 0x96, 0x00, 0x00, 0x80, 0x31, 0x80, 0x65, 0xB0, 0x83, 0x11, 0x17, 0xD6, 0x83, 0x00, 0x90, 0x00 };
            slot.activeProtocol = SCARD_PROTOCOL_T1;
            slot.supportedProtocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
            slot.pin = "123456";
            slot.pinRemainingAttempts = 3;
            m_readers[slot.readerName] = slot;
        }

        // 2. Virtual FIDO2 / Passkey Security Token Reader
        {
            SmartCardSlot slot;
            slot.readerName = L"MicaNT FIDO2 NFC Security Key 0";
            slot.cardPresent = true;
            slot.cardName = L"MicaNT FIDO2 / WebAuthn Token";
            // FIDO2 ATR: 3B 80 80 01 01 (5 bytes)
            slot.atr = { 0x3B, 0x80, 0x80, 0x01, 0x01 };
            slot.activeProtocol = SCARD_PROTOCOL_T1;
            slot.supportedProtocols = SCARD_PROTOCOL_T1;
            slot.pin = "1234";
            slot.pinRemainingAttempts = 3;
            m_readers[slot.readerName] = slot;
        }

        // 3. Virtual Empty Reader
        {
            SmartCardSlot slot;
            slot.readerName = L"MicaNT Empty SmartCard Reader 1";
            slot.cardPresent = false;
            slot.activeProtocol = SCARD_PROTOCOL_UNDEFINED;
            slot.supportedProtocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
            m_readers[slot.readerName] = slot;
        }
    }

    void registerScmServices() {
        auto& scm = scm::ServiceControlManager::get();

        // 1. ScardSvr: Smart Card Resource Manager Service
        auto scardRec = std::make_shared<scm::ServiceRecord>();
        scardRec->serviceName = L"ScardSvr";
        scardRec->displayName = L"Smart Card";
        scardRec->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        scardRec->startType = scm::SERVICE_AUTO_START;
        scardRec->errorControl = scm::SERVICE_ERROR_NORMAL;
        scardRec->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k LocalServiceAndNoImpersonation";
        scardRec->loadOrderGroup = L"LocalServiceAndNoImpersonation";
        scardRec->status.dwServiceType = scardRec->serviceType;
        scardRec->status.dwCurrentState = scm::SERVICE_RUNNING;
        scardRec->status.dwProcessId = 1120;
        scm.registerServiceRecord(scardRec);

        // 2. CertPropSvr: Certificate Propagation Service
        auto certPropRec = std::make_shared<scm::ServiceRecord>();
        certPropRec->serviceName = L"CertPropSvr";
        certPropRec->displayName = L"Certificate Propagation";
        certPropRec->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        certPropRec->startType = scm::SERVICE_DEMAND_START;
        certPropRec->errorControl = scm::SERVICE_ERROR_NORMAL;
        certPropRec->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k netsvcs";
        certPropRec->loadOrderGroup = L"netsvcs";
        certPropRec->status.dwServiceType = certPropRec->serviceType;
        certPropRec->status.dwCurrentState = scm::SERVICE_RUNNING;
        certPropRec->status.dwProcessId = 1124;
        scm.registerServiceRecord(certPropRec);
    }

public:
    static SmartCardManager& get() noexcept {
        static SmartCardManager instance;
        return instance;
    }

    SmartCardManager(const SmartCardManager&) = delete;
    SmartCardManager& operator=(const SmartCardManager&) = delete;

    void resetToDefault() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_readers.clear();
        m_activeContexts.clear();
        m_connections.clear();
        m_nextContextId = 0x1000;
        m_nextHandleId = 0x5000;
        m_serviceRunning = true;
        initDefaultReaders();
    }

    SCARDCONTEXT establishContext(uint32_t /*dwScope*/) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_serviceRunning) return 0;
        SCARDCONTEXT ctx = m_nextContextId++;
        m_activeContexts.push_back(ctx);
        return ctx;
    }

    bool isValidContext(SCARDCONTEXT ctx) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return std::find(m_activeContexts.begin(), m_activeContexts.end(), ctx) != m_activeContexts.end();
    }

    bool releaseContext(SCARDCONTEXT ctx) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find(m_activeContexts.begin(), m_activeContexts.end(), ctx);
        if (it == m_activeContexts.end()) return false;
        m_activeContexts.erase(it);

        // Disconnect all connections created under this context
        for (auto cit = m_connections.begin(); cit != m_connections.end();) {
            if (cit->second.context == ctx) {
                cit = m_connections.erase(cit);
            } else {
                ++cit;
            }
        }
        return true;
    }

    std::vector<std::wstring> getReaderNames() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<std::wstring> result;
        for (const auto& [name, _] : m_readers) {
            result.push_back(name);
        }
        return result;
    }

    bool getReaderSlot(const std::wstring& name, SmartCardSlot& slot) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_readers.find(name);
        if (it != m_readers.end()) {
            slot = it->second;
            return true;
        }
        return false;
    }

    SCARDHANDLE connectCard(
        SCARDCONTEXT ctx,
        const std::wstring& readerName,
        uint32_t shareMode,
        uint32_t preferredProtocols,
        uint32_t& activeProtocol
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (std::find(m_activeContexts.begin(), m_activeContexts.end(), ctx) == m_activeContexts.end()) {
            return 0;
        }

        auto it = m_readers.find(readerName);
        if (it == m_readers.end()) return 0;
        if (!it->second.cardPresent) return 0;

        uint32_t matchedProto = it->second.supportedProtocols & preferredProtocols;
        if (matchedProto == 0 && preferredProtocols != SCARD_PROTOCOL_UNDEFINED) {
            return 0;
        }

        if (matchedProto & SCARD_PROTOCOL_T1) {
            activeProtocol = SCARD_PROTOCOL_T1;
        } else if (matchedProto & SCARD_PROTOCOL_T0) {
            activeProtocol = SCARD_PROTOCOL_T0;
        } else {
            activeProtocol = it->second.activeProtocol;
        }

        SCARDHANDLE hCard = m_nextHandleId++;
        SmartCardConnection conn;
        conn.handle = hCard;
        conn.context = ctx;
        conn.readerName = readerName;
        conn.shareMode = shareMode;
        conn.activeProtocol = activeProtocol;
        m_connections[hCard] = conn;
        return hCard;
    }

    bool disconnectCard(SCARDHANDLE hCard, uint32_t disposition) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_connections.find(hCard);
        if (it == m_connections.end()) return false;

        if (disposition == SCARD_RESET_CARD || disposition == SCARD_UNPOWER_CARD) {
            auto rit = m_readers.find(it->second.readerName);
            if (rit != m_readers.end() && rit->second.cardPresent) {
                rit->second.pinRemainingAttempts = 3;
            }
        } else if (disposition == SCARD_EJECT_CARD) {
            auto rit = m_readers.find(it->second.readerName);
            if (rit != m_readers.end()) {
                rit->second.cardPresent = false;
            }
        }

        m_connections.erase(it);
        return true;
    }

    bool getCardStatus(
        SCARDHANDLE hCard,
        std::wstring& readerName,
        uint32_t& state,
        uint32_t& protocol,
        std::vector<uint8_t>& atr
    ) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_connections.find(hCard);
        if (it == m_connections.end()) return false;

        readerName = it->second.readerName;
        protocol = it->second.activeProtocol;

        auto rit = m_readers.find(readerName);
        if (rit != m_readers.end() && rit->second.cardPresent) {
            state = SCARD_STATE_PRESENT | SCARD_STATE_ATRMATCH | SCARD_STATE_INUSE;
            atr = rit->second.atr;
        } else {
            state = SCARD_STATE_EMPTY;
            atr.clear();
        }
        return true;
    }

    // ISO 7816-4 APDU Protocol Processor
    int32_t transmitApdu(
        SCARDHANDLE hCard,
        const uint8_t* sendBuf,
        uint32_t sendLen,
        uint8_t* recvBuf,
        uint32_t& recvLen
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_connections.find(hCard);
        if (it == m_connections.end()) return SCARD_E_INVALID_HANDLE;

        auto rit = m_readers.find(it->second.readerName);
        if (rit == m_readers.end() || !rit->second.cardPresent) return SCARD_E_NO_SMARTCARD;
        if (!sendBuf || sendLen < 4 || !recvBuf || recvLen < 2) return SCARD_E_INVALID_PARAMETER;

        uint8_t cla = sendBuf[0];
        uint8_t ins = sendBuf[1];
        uint8_t p1  = sendBuf[2];
        uint8_t p2  = sendBuf[3];

        std::vector<uint8_t> resp;

        // 1. SELECT Application (INS = 0xA4)
        if (ins == 0xA4 && p1 == 0x04) {
            uint8_t lc = (sendLen > 4) ? sendBuf[4] : 0;
            if (sendLen >= 5 + lc) {
                std::vector<uint8_t> aid(sendBuf + 5, sendBuf + 5 + lc);

                // NIST PIV AID: A0 00 00 03 08 00 00 10 00
                const uint8_t pivAid[] = { 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00 };
                // FIDO2 AID: A0 00 00 06 47 2F 00 01
                const uint8_t fido2Aid[] = { 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01 };

                if (aid.size() >= sizeof(pivAid) && std::memcmp(aid.data(), pivAid, sizeof(pivAid)) == 0) {
                    // Application Property Template: 61 11 4F ...
                    resp = { 0x61, 0x09, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x90, 0x00 };
                } else if (aid.size() >= sizeof(fido2Aid) && std::memcmp(aid.data(), fido2Aid, sizeof(fido2Aid)) == 0) {
                    resp = { 0x61, 0x08, 0x4F, 0x06, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x90, 0x00 };
                } else {
                    // File / AID Not Found: 6A 82
                    resp = { 0x6A, 0x82 };
                }
            } else {
                resp = { 0x67, 0x00 }; // Wrong length
            }
        }
        // 2. VERIFY PIN (INS = 0x20)
        else if (ins == 0x20) {
            uint8_t lc = (sendLen > 4) ? sendBuf[4] : 0;
            if (lc == 0) {
                // PIN status check
                if (rit->second.pinRemainingAttempts > 0) {
                    resp = { 0x90, 0x00 }; // PIN verified / ready
                } else {
                    resp = { 0x69, 0x83 }; // Authentication method blocked
                }
            } else if (sendLen >= 5 + lc) {
                std::string submittedPin(reinterpret_cast<const char*>(sendBuf + 5), lc);
                // Strip 0xFF padding
                while (!submittedPin.empty() && static_cast<uint8_t>(submittedPin.back()) == 0xFF) {
                    submittedPin.pop_back();
                }

                if (submittedPin == rit->second.pin) {
                    rit->second.pinRemainingAttempts = 3;
                    resp = { 0x90, 0x00 }; // Success
                } else {
                    rit->second.pinRemainingAttempts = std::max(0, rit->second.pinRemainingAttempts - 1);
                    uint8_t remaining = static_cast<uint8_t>(rit->second.pinRemainingAttempts);
                    resp = { 0x63, static_cast<uint8_t>(0xC0 | remaining) }; // 63 CX: Verification failed, X retries left
                }
            } else {
                resp = { 0x67, 0x00 };
            }
        }
        // 3. GET DATA (INS = 0xCB)
        else if (ins == 0xCB) {
            // Return synthetic Cardholder Unique Identifier (CHUID)
            resp = {
                0x53, 0x1A, // CHUID Tag
                0x30, 0x18,
                0x04, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                0x02, 0x04, 0x00, 0x01, 0x26, 0x10,
                0x90, 0x00
            };
        }
        // Default: Command not supported: 6D 00
        else {
            (void)cla;
            (void)p2;
            resp = { 0x6D, 0x00 };
        }

        if (resp.size() > recvLen) {
            return SCARD_E_INVALID_VALUE;
        }

        std::memcpy(recvBuf, resp.data(), resp.size());
        recvLen = static_cast<uint32_t>(resp.size());
        return SCARD_S_SUCCESS;
    }
};

// ============================================================================
// 3. Win32 Smart Card C Client APIs (winscard.dll)
// ============================================================================

inline int32_t __stdcall SCardEstablishContext(
    uint32_t dwScope,
    const void* pvReserved1,
    const void* pvReserved2,
    SCARDCONTEXT* phContext
) {
    (void)pvReserved1;
    (void)pvReserved2;
    if (!phContext) return SCARD_E_INVALID_PARAMETER;
    *phContext = 0;

    SCARDCONTEXT ctx = SmartCardManager::get().establishContext(dwScope);
    if (ctx == 0) return SCARD_E_NO_SERVICE;
    *phContext = ctx;
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardReleaseContext(SCARDCONTEXT hContext) {
    return SmartCardManager::get().releaseContext(hContext) ? SCARD_S_SUCCESS : SCARD_E_INVALID_HANDLE;
}

inline int32_t __stdcall SCardIsValidContext(SCARDCONTEXT hContext) {
    return SmartCardManager::get().isValidContext(hContext) ? SCARD_S_SUCCESS : SCARD_E_INVALID_HANDLE;
}

inline int32_t __stdcall SCardListReaderGroupsW(
    SCARDCONTEXT hContext,
    wchar_t* mszGroups,
    uint32_t* pcchGroups
) {
    if (!SmartCardManager::get().isValidContext(hContext)) return SCARD_E_INVALID_HANDLE;
    if (!pcchGroups) return SCARD_E_INVALID_PARAMETER;

    const wchar_t* groups = L"SCard$DefaultReaders\0SCard$AllReaders\0\0";
    size_t totalLen = 38; // 21 + 16 + 1

    if (!mszGroups) {
        *pcchGroups = static_cast<uint32_t>(totalLen);
        return SCARD_S_SUCCESS;
    }
    if (*pcchGroups < totalLen) {
        *pcchGroups = static_cast<uint32_t>(totalLen);
        return SCARD_E_INVALID_VALUE;
    }

    std::memcpy(mszGroups, groups, totalLen * sizeof(wchar_t));
    *pcchGroups = static_cast<uint32_t>(totalLen);
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardListReaderGroupsA(
    SCARDCONTEXT hContext,
    char* mszGroups,
    uint32_t* pcchGroups
) {
    if (!SmartCardManager::get().isValidContext(hContext)) return SCARD_E_INVALID_HANDLE;
    if (!pcchGroups) return SCARD_E_INVALID_PARAMETER;

    const char* groups = "SCard$DefaultReaders\0SCard$AllReaders\0\0";
    size_t totalLen = 38;

    if (!mszGroups) {
        *pcchGroups = static_cast<uint32_t>(totalLen);
        return SCARD_S_SUCCESS;
    }
    if (*pcchGroups < totalLen) {
        *pcchGroups = static_cast<uint32_t>(totalLen);
        return SCARD_E_INVALID_VALUE;
    }

    std::memcpy(mszGroups, groups, totalLen);
    *pcchGroups = static_cast<uint32_t>(totalLen);
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardListReadersW(
    SCARDCONTEXT hContext,
    const wchar_t* /*mszGroups*/,
    wchar_t* mszReaders,
    uint32_t* pcchReaders
) {
    if (!SmartCardManager::get().isValidContext(hContext)) return SCARD_E_INVALID_HANDLE;
    if (!pcchReaders) return SCARD_E_INVALID_PARAMETER;

    auto readers = SmartCardManager::get().getReaderNames();
    if (readers.empty()) return SCARD_E_NO_READERS_AVAILABLE;

    size_t needed = 1; // Double null at end
    for (const auto& r : readers) {
        needed += r.size() + 1;
    }

    if (!mszReaders) {
        *pcchReaders = static_cast<uint32_t>(needed);
        return SCARD_S_SUCCESS;
    }

    if (*pcchReaders < needed) {
        *pcchReaders = static_cast<uint32_t>(needed);
        return SCARD_E_INVALID_VALUE;
    }

    wchar_t* p = mszReaders;
    for (const auto& r : readers) {
        std::memcpy(p, r.c_str(), (r.size() + 1) * sizeof(wchar_t));
        p += r.size() + 1;
    }
    *p = L'\0';
    *pcchReaders = static_cast<uint32_t>(needed);
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardListReadersA(
    SCARDCONTEXT hContext,
    const char* /*mszGroups*/,
    char* mszReaders,
    uint32_t* pcchReaders
) {
    if (!SmartCardManager::get().isValidContext(hContext)) return SCARD_E_INVALID_HANDLE;
    if (!pcchReaders) return SCARD_E_INVALID_PARAMETER;

    auto readers = SmartCardManager::get().getReaderNames();
    if (readers.empty()) return SCARD_E_NO_READERS_AVAILABLE;

    size_t needed = 1;
    for (const auto& r : readers) {
        needed += r.size() + 1;
    }

    if (!mszReaders) {
        *pcchReaders = static_cast<uint32_t>(needed);
        return SCARD_S_SUCCESS;
    }

    if (*pcchReaders < needed) {
        *pcchReaders = static_cast<uint32_t>(needed);
        return SCARD_E_INVALID_VALUE;
    }

    char* p = mszReaders;
    for (const auto& r : readers) {
        for (wchar_t wc : r) *p++ = static_cast<char>(wc);
        *p++ = '\0';
    }
    *p = '\0';
    *pcchReaders = static_cast<uint32_t>(needed);
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardConnectW(
    SCARDCONTEXT hContext,
    const wchar_t* szReader,
    uint32_t dwShareMode,
    uint32_t dwPreferredProtocols,
    SCARDHANDLE* phCard,
    uint32_t* pdwActiveProtocol
) {
    if (!szReader || !phCard || !pdwActiveProtocol) return SCARD_E_INVALID_PARAMETER;
    *phCard = 0;
    *pdwActiveProtocol = SCARD_PROTOCOL_UNDEFINED;

    uint32_t active = SCARD_PROTOCOL_UNDEFINED;
    SCARDHANDLE h = SmartCardManager::get().connectCard(
        hContext, szReader, dwShareMode, dwPreferredProtocols, active
    );
    if (h == 0) return SCARD_E_NO_SMARTCARD;

    *phCard = h;
    *pdwActiveProtocol = active;
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardConnectA(
    SCARDCONTEXT hContext,
    const char* szReader,
    uint32_t dwShareMode,
    uint32_t dwPreferredProtocols,
    SCARDHANDLE* phCard,
    uint32_t* pdwActiveProtocol
) {
    if (!szReader) return SCARD_E_INVALID_PARAMETER;
    std::string s(szReader);
    std::wstring ws(s.begin(), s.end());
    return SCardConnectW(hContext, ws.c_str(), dwShareMode, dwPreferredProtocols, phCard, pdwActiveProtocol);
}

inline int32_t __stdcall SCardReconnect(
    SCARDHANDLE hCard,
    uint32_t /*dwShareMode*/,
    uint32_t /*dwPreferredProtocols*/,
    uint32_t /*dwInitialization*/,
    uint32_t* pdwActiveProtocol
) {
    if (pdwActiveProtocol) *pdwActiveProtocol = SCARD_PROTOCOL_T1;
    (void)hCard;
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardDisconnect(
    SCARDHANDLE hCard,
    uint32_t dwDisposition
) {
    return SmartCardManager::get().disconnectCard(hCard, dwDisposition) ? SCARD_S_SUCCESS : SCARD_E_INVALID_HANDLE;
}

inline int32_t __stdcall SCardStatusW(
    SCARDHANDLE hCard,
    wchar_t* mszReaderName,
    uint32_t* pcchReaderLen,
    uint32_t* pdwState,
    uint32_t* pdwProtocol,
    uint8_t* pbAtr,
    uint32_t* pcbAtrLen
) {
    std::wstring rName;
    uint32_t st = 0, proto = 0;
    std::vector<uint8_t> atr;

    if (!SmartCardManager::get().getCardStatus(hCard, rName, st, proto, atr)) {
        return SCARD_E_INVALID_HANDLE;
    }

    if (pdwState) *pdwState = st;
    if (pdwProtocol) *pdwProtocol = proto;

    if (pcchReaderLen) {
        size_t needed = rName.size() + 2;
        if (mszReaderName && *pcchReaderLen >= needed) {
            std::memcpy(mszReaderName, rName.c_str(), (rName.size() + 1) * sizeof(wchar_t));
            mszReaderName[rName.size() + 1] = L'\0';
        }
        *pcchReaderLen = static_cast<uint32_t>(needed);
    }

    if (pcbAtrLen) {
        if (pbAtr && *pcbAtrLen >= atr.size()) {
            std::memcpy(pbAtr, atr.data(), atr.size());
        }
        *pcbAtrLen = static_cast<uint32_t>(atr.size());
    }

    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardStatusA(
    SCARDHANDLE hCard,
    char* mszReaderName,
    uint32_t* pcchReaderLen,
    uint32_t* pdwState,
    uint32_t* pdwProtocol,
    uint8_t* pbAtr,
    uint32_t* pcbAtrLen
) {
    std::wstring rName;
    uint32_t st = 0, proto = 0;
    std::vector<uint8_t> atr;

    if (!SmartCardManager::get().getCardStatus(hCard, rName, st, proto, atr)) {
        return SCARD_E_INVALID_HANDLE;
    }

    if (pdwState) *pdwState = st;
    if (pdwProtocol) *pdwProtocol = proto;

    if (pcchReaderLen) {
        size_t needed = rName.size() + 2;
        if (mszReaderName && *pcchReaderLen >= needed) {
            for (size_t i = 0; i < rName.size(); ++i) mszReaderName[i] = static_cast<char>(rName[i]);
            mszReaderName[rName.size()] = '\0';
            mszReaderName[rName.size() + 1] = '\0';
        }
        *pcchReaderLen = static_cast<uint32_t>(needed);
    }

    if (pcbAtrLen) {
        if (pbAtr && *pcbAtrLen >= atr.size()) {
            std::memcpy(pbAtr, atr.data(), atr.size());
        }
        *pcbAtrLen = static_cast<uint32_t>(atr.size());
    }

    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardGetStatusChangeW(
    SCARDCONTEXT hContext,
    uint32_t /*dwTimeout*/,
    SCARD_READERSTATEW* rgReaderStates,
    uint32_t cReaders
) {
    if (!SmartCardManager::get().isValidContext(hContext)) return SCARD_E_INVALID_HANDLE;
    if (!rgReaderStates && cReaders > 0) return SCARD_E_INVALID_PARAMETER;

    for (uint32_t i = 0; i < cReaders; ++i) {
        auto& rs = rgReaderStates[i];
        if (!rs.szReader) continue;

        SmartCardSlot slot;
        if (SmartCardManager::get().getReaderSlot(rs.szReader, slot)) {
            uint32_t state = 0;
            if (slot.cardPresent) {
                state = SCARD_STATE_PRESENT | SCARD_STATE_ATRMATCH;
                rs.cbAtr = static_cast<uint32_t>(slot.atr.size());
                std::memcpy(rs.rgbAtr, slot.atr.data(), std::min(sizeof(rs.rgbAtr), slot.atr.size()));
            } else {
                state = SCARD_STATE_EMPTY;
                rs.cbAtr = 0;
            }
            if (state != rs.dwCurrentState) {
                state |= SCARD_STATE_CHANGED;
            }
            rs.dwEventState = state;
        } else {
            rs.dwEventState = SCARD_STATE_UNKNOWN | SCARD_STATE_UNAVAILABLE;
            rs.cbAtr = 0;
        }
    }
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardGetStatusChangeA(
    SCARDCONTEXT hContext,
    uint32_t dwTimeout,
    SCARD_READERSTATEA* rgReaderStates,
    uint32_t cReaders
) {
    if (!SmartCardManager::get().isValidContext(hContext)) return SCARD_E_INVALID_HANDLE;
    if (!rgReaderStates && cReaders > 0) return SCARD_E_INVALID_PARAMETER;

    for (uint32_t i = 0; i < cReaders; ++i) {
        auto& rsa = rgReaderStates[i];
        if (!rsa.szReader) continue;
        std::string s(rsa.szReader);
        std::wstring ws(s.begin(), s.end());

        SCARD_READERSTATEW rsw{};
        rsw.szReader = ws.c_str();
        rsw.dwCurrentState = rsa.dwCurrentState;
        SCardGetStatusChangeW(hContext, dwTimeout, &rsw, 1);
        rsa.dwEventState = rsw.dwEventState;
        rsa.cbAtr = rsw.cbAtr;
        std::memcpy(rsa.rgbAtr, rsw.rgbAtr, sizeof(rsa.rgbAtr));
    }
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardTransmit(
    SCARDHANDLE hCard,
    const SCARD_IO_REQUEST* /*pioSendPci*/,
    const uint8_t* pbSendBuffer,
    uint32_t cbSendLength,
    SCARD_IO_REQUEST* pioRecvPci,
    uint8_t* pbRecvBuffer,
    uint32_t* pcbRecvLength
) {
    if (!pcbRecvLength) return SCARD_E_INVALID_PARAMETER;
    if (pioRecvPci) {
        pioRecvPci->dwProtocol = SCARD_PROTOCOL_T1;
        pioRecvPci->cbPciLength = sizeof(SCARD_IO_REQUEST);
    }
    return SmartCardManager::get().transmitApdu(
        hCard, pbSendBuffer, cbSendLength, pbRecvBuffer, *pcbRecvLength
    );
}

inline int32_t __stdcall SCardControl(
    SCARDHANDLE hCard,
    uint32_t /*dwControlCode*/,
    const void* /*lpInBuffer*/,
    uint32_t /*cbInBufferSize*/,
    void* /*lpOutBuffer*/,
    uint32_t /*cbOutBufferSize*/,
    uint32_t* lpBytesReturned
) {
    (void)hCard;
    if (lpBytesReturned) *lpBytesReturned = 0;
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardGetAttrib(
    SCARDHANDLE hCard,
    uint32_t /*dwAttrId*/,
    uint8_t* pbAttr,
    uint32_t* pcbAttrLen
) {
    (void)hCard;
    if (!pcbAttrLen) return SCARD_E_INVALID_PARAMETER;
    if (pbAttr && *pcbAttrLen >= 4) {
        uint32_t val = 0x00010000;
        std::memcpy(pbAttr, &val, 4);
    }
    *pcbAttrLen = 4;
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardSetAttrib(
    SCARDHANDLE hCard,
    uint32_t /*dwAttrId*/,
    const uint8_t* /*pbAttr*/,
    uint32_t /*cbAttrLen*/
) {
    (void)hCard;
    return SCARD_S_SUCCESS;
}

inline int32_t __stdcall SCardCancel(SCARDCONTEXT hContext) {
    return SmartCardManager::get().isValidContext(hContext) ? SCARD_S_SUCCESS : SCARD_E_INVALID_HANDLE;
}

inline int32_t __stdcall SCardFreeMemory(SCARDCONTEXT hContext, void* pvMem) {
    (void)hContext;
    (void)pvMem;
    return SCARD_S_SUCCESS;
}

// ============================================================================
// 4. Dynamic Loader Registration
// ============================================================================

inline void InitializeWinSCardSubsystemExports() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    // Ensure SCM services are established
    SmartCardManager::get();

    auto& ldr = ldr::DynamicLoader::get();

    // 1. winscard.dll exports
    ldr.registerExport("winscard.dll", "SCardEstablishContext", reinterpret_cast<void*>(SCardEstablishContext));
    ldr.registerExport("winscard.dll", "SCardReleaseContext", reinterpret_cast<void*>(SCardReleaseContext));
    ldr.registerExport("winscard.dll", "SCardIsValidContext", reinterpret_cast<void*>(SCardIsValidContext));
    ldr.registerExport("winscard.dll", "SCardListReaderGroupsW", reinterpret_cast<void*>(SCardListReaderGroupsW));
    ldr.registerExport("winscard.dll", "SCardListReaderGroupsA", reinterpret_cast<void*>(SCardListReaderGroupsA));
    ldr.registerExport("winscard.dll", "SCardListReadersW", reinterpret_cast<void*>(SCardListReadersW));
    ldr.registerExport("winscard.dll", "SCardListReadersA", reinterpret_cast<void*>(SCardListReadersA));
    ldr.registerExport("winscard.dll", "SCardConnectW", reinterpret_cast<void*>(SCardConnectW));
    ldr.registerExport("winscard.dll", "SCardConnectA", reinterpret_cast<void*>(SCardConnectA));
    ldr.registerExport("winscard.dll", "SCardReconnect", reinterpret_cast<void*>(SCardReconnect));
    ldr.registerExport("winscard.dll", "SCardDisconnect", reinterpret_cast<void*>(SCardDisconnect));
    ldr.registerExport("winscard.dll", "SCardStatusW", reinterpret_cast<void*>(SCardStatusW));
    ldr.registerExport("winscard.dll", "SCardStatusA", reinterpret_cast<void*>(SCardStatusA));
    ldr.registerExport("winscard.dll", "SCardGetStatusChangeW", reinterpret_cast<void*>(SCardGetStatusChangeW));
    ldr.registerExport("winscard.dll", "SCardGetStatusChangeA", reinterpret_cast<void*>(SCardGetStatusChangeA));
    ldr.registerExport("winscard.dll", "SCardTransmit", reinterpret_cast<void*>(SCardTransmit));
    ldr.registerExport("winscard.dll", "SCardControl", reinterpret_cast<void*>(SCardControl));
    ldr.registerExport("winscard.dll", "SCardGetAttrib", reinterpret_cast<void*>(SCardGetAttrib));
    ldr.registerExport("winscard.dll", "SCardSetAttrib", reinterpret_cast<void*>(SCardSetAttrib));
    ldr.registerExport("winscard.dll", "SCardCancel", reinterpret_cast<void*>(SCardCancel));
    ldr.registerExport("winscard.dll", "SCardFreeMemory", reinterpret_cast<void*>(SCardFreeMemory));

    // Global PCIs
    ldr.registerExport("winscard.dll", "g_rgSCardT0Pci", const_cast<void*>(static_cast<const void*>(&g_rgSCardT0Pci)));
    ldr.registerExport("winscard.dll", "g_rgSCardT1Pci", const_cast<void*>(static_cast<const void*>(&g_rgSCardT1Pci)));
    ldr.registerExport("winscard.dll", "g_rgSCardRawPci", const_cast<void*>(static_cast<const void*>(&g_rgSCardRawPci)));

    // 2. scredir.dll exports
    ldr.registerExport("scredir.dll", "SCardEstablishContext", reinterpret_cast<void*>(SCardEstablishContext));
    ldr.registerExport("scredir.dll", "SCardReleaseContext", reinterpret_cast<void*>(SCardReleaseContext));
    ldr.registerExport("scredir.dll", "SCardListReadersW", reinterpret_cast<void*>(SCardListReadersW));

    // 3. certprop.dll exports
    ldr.registerExport("certprop.dll", "DllRegisterServer", reinterpret_cast<void*>(SCardIsValidContext));
    ldr.registerExport("certprop.dll", "DllUnregisterServer", reinterpret_cast<void*>(SCardIsValidContext));
}

} // namespace micant::scard
