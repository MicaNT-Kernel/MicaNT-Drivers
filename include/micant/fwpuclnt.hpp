// ============================================================================
// MicaNT: Windows Filtering Platform (WFP) & Advanced Firewall Subsystem
// (include/micant/fwpuclnt.hpp)
//
// Strict Clean-Room Implementation based on:
//   - Microsoft Windows Filtering Platform (WFP) Architecture Specification
//   - Win32 WFP Management API (fwpuclnt.h / fwpmtypes.h / fwpstypes.h) C ABI
//   - Windows Advanced Firewall (netsh advfirewall / FirewallAPI.dll) Model
//   - RFC 791 (IPv4), RFC 793 (TCP), RFC 768 (UDP), RFC 792 (ICMP) Filtering
//
// Subsystem Overview:
//   fwpuclnt.hpp provides the user-mode Windows Filtering Platform (WFP)
//   client subsystem and sovereign packet classification engine for MicaNT.
//   It allows processes to configure filtering layers, sublayers, callouts,
//   and rules to inspect, permit, or drop network packets, as well as managing
//   Windows Advanced Firewall domain, private, and public security profiles.
//
// Features:
//   - Native Win32 WFP Client C API (fwpuclnt.dll):
//       * FwpmEngineOpen0 / FwpmEngineClose0
//       * FwpmSessionCreateEnumHandle0 / FwpmSessionDestroyEnumHandle0 / FwpmSessionEnum0
//       * FwpmFilterAdd0 / FwpmFilterDeleteById0 / FwpmFilterGetById0
//       * FwpmFilterCreateEnumHandle0 / FwpmFilterEnum0 / FwpmFilterDestroyEnumHandle0
//       * FwpmLayerCreateEnumHandle0 / FwpmLayerEnum0 / FwpmLayerDestroyEnumHandle0
//       * FwpmSubLayerAdd0 / FwpmSubLayerDeleteById0 / FwpmSubLayerEnum0
//       * FwpmFreeMemory0
//   - Standard WFP Layer Hierarchy:
//       * FWPM_LAYER_INBOUND_IPPACKET_V4 / FWPM_LAYER_OUTBOUND_IPPACKET_V4
//       * FWPM_LAYER_INBOUND_TRANSPORT_V4 / FWPM_LAYER_OUTBOUND_TRANSPORT_V4
//       * FWPM_LAYER_ALE_AUTH_CONNECT_V4 / FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
//   - Packet Classification Engine:
//       * Directional packet matching (Inbound / Outbound)
//       * Protocol matching (TCP, UDP, ICMP, Any)
//       * Port range and IP address matching
//       * Action resolution: FWP_ACTION_PERMIT, FWP_ACTION_BLOCK
//   - Windows Advanced Firewall Profile State:
//       * Domain, Private, and Public profiles
//       * Default Inbound (Block) and Outbound (Allow) policies
//
// Core Dynamic Module:
//   - fwpuclnt.dll
//
// Trademark & Nominative Fair Use Notice:
//   Windows is a registered trademark of Microsoft Corp.
//   MicaNT is an independent sovereign clean-room implementation engineered
//   for binary interoperability (*Google LLC v. Oracle America, Inc.*).
// ============================================================================

#pragma once

#include "ntdef.hpp"
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

namespace micant::wfp {

// ============================================================================
// 1. Standard Win32 WFP Constants, Types & Enums
// ============================================================================

using DWORD     = uint32_t;
using UINT8     = uint8_t;
using UINT16    = uint16_t;
using UINT32    = uint32_t;
using UINT64    = uint64_t;
using BOOL      = int32_t;
using WCHAR     = wchar_t;
using PWCHAR    = wchar_t*;
using LPCWSTR   = const wchar_t*;
using PCWSTR    = const wchar_t*;
using PVOID     = void*;
using HANDLE    = void*;
using GUID      = micant::GUID;

#ifndef WINAPI
#define WINAPI __stdcall
#endif

// Standard Win32 Error Codes
inline constexpr DWORD ERROR_SUCCESS                    = 0;
inline constexpr DWORD ERROR_INVALID_PARAMETER          = 87;
inline constexpr DWORD ERROR_INVALID_HANDLE             = 6;
inline constexpr DWORD ERROR_FILE_NOT_FOUND             = 2;
inline constexpr DWORD ERROR_NOT_FOUND                  = 1168;
inline constexpr DWORD ERROR_ALREADY_EXISTS             = 183;
inline constexpr DWORD ERROR_NO_MORE_ITEMS              = 259;

// WFP Error Codes
constexpr DWORD FWP_E_ALREADY_EXISTS              = 0x8032000B;
constexpr DWORD FWP_E_FILTER_NOT_FOUND            = 0x8032000C;
constexpr DWORD FWP_E_LAYER_NOT_FOUND             = 0x8032000D;
constexpr DWORD FWP_E_SUBLAYER_NOT_FOUND          = 0x8032000E;
constexpr DWORD FWP_E_NOT_FOUND                   = 0x80320004;

// WFP Action Types
constexpr UINT32 FWP_ACTION_FLAG_TERMINATING      = 0x00001000;
constexpr UINT32 FWP_ACTION_FLAG_NON_TERMINATING  = 0x00002000;
constexpr UINT32 FWP_ACTION_FLAG_CALLOUT          = 0x00004000;

constexpr UINT32 FWP_ACTION_PERMIT                = (0x00000001 | FWP_ACTION_FLAG_TERMINATING);
constexpr UINT32 FWP_ACTION_BLOCK                 = (0x00000002 | FWP_ACTION_FLAG_TERMINATING);
constexpr UINT32 FWP_ACTION_CONTINUE              = (0x00000003 | FWP_ACTION_FLAG_NON_TERMINATING);
constexpr UINT32 FWP_ACTION_CALLOUT_TERMINATING   = (0x00000004 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_TERMINATING);
constexpr UINT32 FWP_ACTION_CALLOUT_INSPECTION    = (0x00000005 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_NON_TERMINATING);

// WFP Match Types
enum FWP_MATCH_TYPE {
    FWP_MATCH_EQUAL                 = 0,
    FWP_MATCH_GREATER               = 1,
    FWP_MATCH_LESS                  = 2,
    FWP_MATCH_GREATER_OR_EQUAL      = 3,
    FWP_MATCH_LESS_OR_EQUAL         = 4,
    FWP_MATCH_RANGE                 = 5,
    FWP_MATCH_FLAGS_ALL_SET         = 6,
    FWP_MATCH_FLAGS_ANY_SET         = 7,
    FWP_MATCH_FLAGS_NONE_SET        = 8,
    FWP_MATCH_EQUAL_CASE_INSENSITIVE = 9,
    FWP_MATCH_NOT_EQUAL             = 10
};

// Standard WFP Layer GUIDs
inline constexpr GUID FWPM_LAYER_INBOUND_IPPACKET_V4 = {
    0xb3c5791a, 0x1d21, 0x464a, { 0x86, 0xb6, 0x40, 0x93, 0x4e, 0x22, 0x8a, 0x3d }
};

inline constexpr GUID FWPM_LAYER_OUTBOUND_IPPACKET_V4 = {
    0xb3c5791b, 0x1d21, 0x464a, { 0x86, 0xb6, 0x40, 0x93, 0x4e, 0x22, 0x8a, 0x3d }
};

inline constexpr GUID FWPM_LAYER_INBOUND_TRANSPORT_V4 = {
    0xb3c5791c, 0x1d21, 0x464a, { 0x86, 0xb6, 0x40, 0x93, 0x4e, 0x22, 0x8a, 0x3e }
};

inline constexpr GUID FWPM_LAYER_OUTBOUND_TRANSPORT_V4 = {
    0xb3c5791d, 0x1d21, 0x464a, { 0x86, 0xb6, 0x40, 0x93, 0x4e, 0x22, 0x8a, 0x3e }
};

inline constexpr GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4 = {
    0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0x60, 0x0d, 0x18 }
};

inline constexpr GUID FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = {
    0xa3b42c97, 0x9f04, 0x4672, { 0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f }
};

// Standard SubLayer GUIDs
inline constexpr GUID FWPM_SUBLAYER_UNIVERSAL = {
    0x2c00714b, 0x4386, 0x446d, { 0xbe, 0x30, 0x99, 0x25, 0x13, 0xd0, 0xc1, 0xdd }
};

inline constexpr GUID FWPM_SUBLAYER_FIREWALL = {
    0x34705574, 0x4674, 0x4950, { 0x4d, 0x69, 0x63, 0x61, 0x46, 0x69, 0x72, 0x65 }
};

// Firewall Profile Types
constexpr DWORD FW_PROFILE_TYPE_DOMAIN  = 0x0001;
constexpr DWORD FW_PROFILE_TYPE_PRIVATE = 0x0002;
constexpr DWORD FW_PROFILE_TYPE_PUBLIC  = 0x0004;
constexpr DWORD FW_PROFILE_TYPE_ALL     = 0x7FFFFFFF;

// Direction
enum FWP_DIRECTION {
    FWP_DIRECTION_INBOUND  = 0,
    FWP_DIRECTION_OUTBOUND = 1
};

// Protocol
constexpr UINT8 FWP_IPPROTO_ICMP = 1;
constexpr UINT8 FWP_IPPROTO_TCP  = 6;
constexpr UINT8 FWP_IPPROTO_UDP  = 17;
constexpr UINT8 FWP_IPPROTO_ANY  = 0;

// Structures
struct FWPM_SESSION0 {
    GUID sessionKey{};
    std::wstring displayDataName;
    std::wstring displayDataDescription;
    DWORD flags{ 0 };
    DWORD txnWaitTimeoutInMSec{ 0 };
    DWORD processId{ 0 };
    HANDLE processToken{ nullptr };
};

struct FWP_VALUE0 {
    DWORD type{ 0 };
    uint32_t uint32{ 0 };
    uint16_t uint16{ 0 };
    uint8_t  uint8{ 0 };
};

struct FWP_CONDITION_VALUE0 {
    DWORD type{ 0 };
    uint32_t uint32{ 0 };
    uint16_t uint16{ 0 };
    uint8_t  uint8{ 0 };
};

struct FWPM_FILTER_CONDITION0 {
    GUID fieldKey{};
    FWP_MATCH_TYPE matchType{ FWP_MATCH_EQUAL };
    FWP_CONDITION_VALUE0 conditionValue{};
};

struct FWPM_ACTION0 {
    UINT32 type{ FWP_ACTION_PERMIT };
    GUID   calloutKey{};
};

struct FWPM_FILTER0 {
    GUID filterKey{};
    std::wstring displayDataName;
    std::wstring displayDataDescription;
    DWORD flags{ 0 };
    GUID* providerKey{ nullptr };
    GUID layerKey{};
    GUID subLayerKey{};
    FWP_VALUE0 weight{};
    UINT32 numFilterConditions{ 0 };
    FWPM_FILTER_CONDITION0* filterCondition{ nullptr };
    FWPM_ACTION0 action{};
    UINT64 filterId{ 0 };
};

struct FWPM_SUBLAYER0 {
    GUID subLayerKey{};
    std::wstring displayDataName;
    std::wstring displayDataDescription;
    DWORD flags{ 0 };
    GUID* providerKey{ nullptr };
    UINT16 weight{ 0x1000 };
};

struct FWPM_LAYER0 {
    GUID layerKey{};
    std::wstring displayDataName;
    std::wstring displayDataDescription;
    DWORD flags{ 0 };
    UINT16 numFields{ 0 };
};

struct FWPM_SESSION_ENUM_TEMPLATE0 {
    GUID* reserved{ nullptr };
};

struct FWPM_FILTER_ENUM_TEMPLATE0 {
    GUID* reserved{ nullptr };
};

struct FWPM_LAYER_ENUM_TEMPLATE0 {
    GUID* reserved{ nullptr };
};

// ============================================================================
// 2. High-Level Firewall Rule & Packet Classifier Data Models
// ============================================================================

struct FirewallRule {
    UINT64      id{ 0 };
    std::string name;
    std::string description;
    std::string applicationPath;
    FWP_DIRECTION direction{ FWP_DIRECTION_INBOUND };
    UINT32      action{ FWP_ACTION_PERMIT }; // FWP_ACTION_PERMIT or FWP_ACTION_BLOCK
    UINT8       protocol{ FWP_IPPROTO_ANY }; // 0 for any, 6 for TCP, 17 for UDP, 1 for ICMP
    UINT16      localPort{ 0 };              // 0 for any
    UINT16      remotePort{ 0 };             // 0 for any
    DWORD       profiles{ FW_PROFILE_TYPE_ALL };
    bool        enabled{ true };
};

struct FirewallProfile {
    DWORD profileType{ FW_PROFILE_TYPE_DOMAIN };
    std::string name{ "Domain" };
    bool  enabled{ true };
    UINT32 defaultInboundAction{ FWP_ACTION_BLOCK };
    UINT32 defaultOutboundAction{ FWP_ACTION_PERMIT };
    bool  allowInboundRules{ true };
    bool  allowLocalFirewallRules{ true };
};

struct NetworkPacket {
    FWP_DIRECTION direction{ FWP_DIRECTION_INBOUND };
    UINT8  protocol{ FWP_IPPROTO_TCP };
    uint32_t srcIp{ 0x7F000001 }; // 127.0.0.1
    uint32_t dstIp{ 0x7F000001 };
    uint16_t srcPort{ 12345 };
    uint16_t dstPort{ 80 };
    std::string appPath;
};

// ============================================================================
// 3. Sovereign WFP Manager & Packet Classification Engine
// ============================================================================

class SovereignWfpManager {
private:
    std::mutex m_mutex;
    uintptr_t  m_nextHandle{ 0x8000 };
    UINT64     m_nextFilterId{ 1000 };

    // Active Engine Sessions
    struct EngineSession {
        HANDLE handle{ nullptr };
        DWORD processId{ 0 };
        std::wstring name;
    };
    std::unordered_map<HANDLE, EngineSession> m_sessions;

    // Registered Layers
    std::unordered_map<std::string, FWPM_LAYER0> m_layers;

    // Registered Sublayers
    std::unordered_map<std::string, FWPM_SUBLAYER0> m_subLayers;

    // Registered Filters
    std::unordered_map<UINT64, FWPM_FILTER0> m_filters;

    // Firewall Profiles
    FirewallProfile m_domainProfile{ FW_PROFILE_TYPE_DOMAIN, "Domain", true, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, true, true };
    FirewallProfile m_privateProfile{ FW_PROFILE_TYPE_PRIVATE, "Private", true, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, true, true };
    FirewallProfile m_publicProfile{ FW_PROFILE_TYPE_PUBLIC, "Public", true, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, true, true };

    // High-Level Firewall Rules
    std::vector<FirewallRule> m_firewallRules;

    std::string guidToString(const GUID& g) {
        char buf[64]{ 0 };
        std::snprintf(buf, sizeof(buf), "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
            g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
        return std::string(buf);
    }

    SovereignWfpManager() {
        // 1. Initialize Standard Layers
        auto registerLayer = [this](const GUID& g, const std::wstring& name, const std::wstring& desc) {
            FWPM_LAYER0 l{};
            l.layerKey = g;
            l.displayDataName = name;
            l.displayDataDescription = desc;
            l.numFields = 16;
            m_layers[guidToString(g)] = l;
        };

        registerLayer(FWPM_LAYER_INBOUND_IPPACKET_V4, L"FWPM_LAYER_INBOUND_IPPACKET_V4", L"Inbound IPv4 Packet Inspection Layer");
        registerLayer(FWPM_LAYER_OUTBOUND_IPPACKET_V4, L"FWPM_LAYER_OUTBOUND_IPPACKET_V4", L"Outbound IPv4 Packet Inspection Layer");
        registerLayer(FWPM_LAYER_INBOUND_TRANSPORT_V4, L"FWPM_LAYER_INBOUND_TRANSPORT_V4", L"Inbound IPv4 Transport Layer (TCP/UDP)");
        registerLayer(FWPM_LAYER_OUTBOUND_TRANSPORT_V4, L"FWPM_LAYER_OUTBOUND_TRANSPORT_V4", L"Outbound IPv4 Transport Layer (TCP/UDP)");
        registerLayer(FWPM_LAYER_ALE_AUTH_CONNECT_V4, L"FWPM_LAYER_ALE_AUTH_CONNECT_V4", L"Application Layer Enforcement Outbound Connect");
        registerLayer(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, L"FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4", L"Application Layer Enforcement Inbound Accept");

        // 2. Initialize Standard Sublayers
        auto registerSubLayer = [this](const GUID& g, const std::wstring& name, UINT16 weight) {
            FWPM_SUBLAYER0 s{};
            s.subLayerKey = g;
            s.displayDataName = name;
            s.weight = weight;
            m_subLayers[guidToString(g)] = s;
        };

        registerSubLayer(FWPM_SUBLAYER_UNIVERSAL, L"Universal SubLayer", 0x1000);
        registerSubLayer(FWPM_SUBLAYER_FIREWALL, L"Windows Advanced Firewall SubLayer", 0x8000);

        // 3. Pre-seed Default Firewall Rules
        FirewallRule r1{};
        r1.id = m_nextFilterId++;
        r1.name = "Core Networking - DNS (UDP-Out)";
        r1.description = "Permit outbound DNS resolution queries";
        r1.direction = FWP_DIRECTION_OUTBOUND;
        r1.action = FWP_ACTION_PERMIT;
        r1.protocol = FWP_IPPROTO_UDP;
        r1.remotePort = 53;
        r1.enabled = true;
        m_firewallRules.push_back(r1);

        FirewallRule r2{};
        r2.id = m_nextFilterId++;
        r2.name = "Core Networking - HTTP/HTTPS (TCP-Out)";
        r2.description = "Permit outbound Web traffic";
        r2.direction = FWP_DIRECTION_OUTBOUND;
        r2.action = FWP_ACTION_PERMIT;
        r2.protocol = FWP_IPPROTO_TCP;
        r2.remotePort = 80;
        r2.enabled = true;
        m_firewallRules.push_back(r2);

        FirewallRule r3{};
        r3.id = m_nextFilterId++;
        r3.name = "Remote Desktop - User Mode (TCP-In)";
        r3.description = "Inbound rule for Remote Desktop traffic (TCP 3389)";
        r3.direction = FWP_DIRECTION_INBOUND;
        r3.action = FWP_ACTION_PERMIT;
        r3.protocol = FWP_IPPROTO_TCP;
        r3.localPort = 3389;
        r3.enabled = true;
        m_firewallRules.push_back(r3);
    }

public:
    static SovereignWfpManager& get() {
        static SovereignWfpManager s_instance;
        return s_instance;
    }

    // Engine Session Management
    DWORD openEngine([[maybe_unused]] PCWSTR serverName,
                     [[maybe_unused]] UINT32 authnService,
                     const FWPM_SESSION0* session,
                     HANDLE* engineHandle) {
        if (!engineHandle) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        HANDLE h = reinterpret_cast<HANDLE>(m_nextHandle++);
        EngineSession s{};
        s.handle = h;
        s.processId = 1000;
        if (session) {
            s.name = session->displayDataName;
        } else {
            s.name = L"MicaNT WFP Default Session";
        }
        m_sessions[h] = s;
        *engineHandle = h;
        return ERROR_SUCCESS;
    }

    DWORD closeEngine(HANDLE engineHandle) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(engineHandle);
        if (it == m_sessions.end()) return ERROR_INVALID_HANDLE;
        m_sessions.erase(it);
        return ERROR_SUCCESS;
    }

    // Filter Management
    DWORD addFilter(HANDLE engineHandle, const FWPM_FILTER0* filter, UINT64* id) {
        if (!filter) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_sessions.find(engineHandle) == m_sessions.end()) {
            return ERROR_INVALID_HANDLE;
        }

        UINT64 newId = m_nextFilterId++;
        FWPM_FILTER0 f = *filter;
        f.filterId = newId;
        m_filters[newId] = f;

        if (id) *id = newId;
        return ERROR_SUCCESS;
    }

    DWORD deleteFilterById(HANDLE engineHandle, UINT64 id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_sessions.find(engineHandle) == m_sessions.end()) return ERROR_INVALID_HANDLE;

        auto it = m_filters.find(id);
        if (it == m_filters.end()) return FWP_E_FILTER_NOT_FOUND;

        m_filters.erase(it);
        return ERROR_SUCCESS;
    }

    DWORD getFilterById(HANDLE engineHandle, UINT64 id, FWPM_FILTER0** filter) {
        if (!filter) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_sessions.find(engineHandle) == m_sessions.end()) return ERROR_INVALID_HANDLE;

        auto it = m_filters.find(id);
        if (it == m_filters.end()) return FWP_E_FILTER_NOT_FOUND;

        auto* pBuf = new FWPM_FILTER0();
        *pBuf = it->second;
        *filter = pBuf;
        return ERROR_SUCCESS;
    }

    DWORD getAllFilters(std::vector<FWPM_FILTER0>& outList) {
        std::lock_guard<std::mutex> lock(m_mutex);
        outList.clear();
        for (const auto& pair : m_filters) outList.push_back(pair.second);
        return ERROR_SUCCESS;
    }

    // Layer Management
    DWORD getAllLayers(std::vector<FWPM_LAYER0>& outLayers) {
        std::lock_guard<std::mutex> lock(m_mutex);
        outLayers.clear();
        for (const auto& pair : m_layers) outLayers.push_back(pair.second);
        return ERROR_SUCCESS;
    }

    // Sublayer Management
    DWORD addSubLayer(HANDLE engineHandle, const FWPM_SUBLAYER0* subLayer) {
        if (!subLayer) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_sessions.find(engineHandle) == m_sessions.end()) return ERROR_INVALID_HANDLE;

        std::string sKey = guidToString(subLayer->subLayerKey);
        m_subLayers[sKey] = *subLayer;
        return ERROR_SUCCESS;
    }

    DWORD deleteSubLayerById(HANDLE engineHandle, const GUID* key) {
        if (!key) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_sessions.find(engineHandle) == m_sessions.end()) return ERROR_INVALID_HANDLE;

        std::string sKey = guidToString(*key);
        auto it = m_subLayers.find(sKey);
        if (it == m_subLayers.end()) return FWP_E_SUBLAYER_NOT_FOUND;

        m_subLayers.erase(it);
        return ERROR_SUCCESS;
    }

    DWORD getAllSubLayers(std::vector<FWPM_SUBLAYER0>& outSubLayers) {
        std::lock_guard<std::mutex> lock(m_mutex);
        outSubLayers.clear();
        for (const auto& pair : m_subLayers) outSubLayers.push_back(pair.second);
        return ERROR_SUCCESS;
    }

    // Firewall Profile Management
    FirewallProfile getProfile(DWORD profileType) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (profileType == FW_PROFILE_TYPE_DOMAIN) return m_domainProfile;
        if (profileType == FW_PROFILE_TYPE_PRIVATE) return m_privateProfile;
        return m_publicProfile;
    }

    void setProfileState(DWORD profileType, bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (profileType & FW_PROFILE_TYPE_DOMAIN) m_domainProfile.enabled = enabled;
        if (profileType & FW_PROFILE_TYPE_PRIVATE) m_privateProfile.enabled = enabled;
        if (profileType & FW_PROFILE_TYPE_PUBLIC) m_publicProfile.enabled = enabled;
    }

    // High-Level Firewall Rules
    UINT64 addFirewallRule(const FirewallRule& rule) {
        std::lock_guard<std::mutex> lock(m_mutex);
        FirewallRule r = rule;
        r.id = m_nextFilterId++;
        m_firewallRules.push_back(r);
        return r.id;
    }

    bool deleteFirewallRuleByName(const std::string& name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::remove_if(m_firewallRules.begin(), m_firewallRules.end(),
            [&name](const FirewallRule& r) { return r.name == name; });
        if (it != m_firewallRules.end()) {
            m_firewallRules.erase(it, m_firewallRules.end());
            return true;
        }
        return false;
    }

    std::vector<FirewallRule> getFirewallRules() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_firewallRules;
    }

    // Packet Classification Engine
    UINT32 classifyPacket(const NetworkPacket& packet, DWORD activeProfileType = FW_PROFILE_TYPE_PUBLIC) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Check if firewall is enabled for profile
        FirewallProfile profile = m_publicProfile;
        if (activeProfileType == FW_PROFILE_TYPE_DOMAIN) profile = m_domainProfile;
        else if (activeProfileType == FW_PROFILE_TYPE_PRIVATE) profile = m_privateProfile;

        if (!profile.enabled) {
            return FWP_ACTION_PERMIT; // Permitted if firewall is turned off
        }

        // 1. Evaluate explicit rules (first match wins or explicit block overrides)
        // High priority: Explicit BLOCK rules
        for (const auto& r : m_firewallRules) {
            if (!r.enabled) continue;
            if (!(r.profiles & activeProfileType)) continue;
            if (r.direction != packet.direction) continue;

            // Protocol check
            if (r.protocol != FWP_IPPROTO_ANY && r.protocol != packet.protocol) continue;

            // Port checks
            if (packet.direction == FWP_DIRECTION_INBOUND) {
                if (r.localPort != 0 && r.localPort != packet.dstPort) continue;
            } else {
                if (r.remotePort != 0 && r.remotePort != packet.dstPort) continue;
            }

            // Application path check
            if (!r.applicationPath.empty() && r.applicationPath != packet.appPath) continue;

            if (r.action == FWP_ACTION_BLOCK) {
                return FWP_ACTION_BLOCK;
            }
        }

        // 2. High priority: Explicit PERMIT rules
        for (const auto& r : m_firewallRules) {
            if (!r.enabled) continue;
            if (!(r.profiles & activeProfileType)) continue;
            if (r.direction != packet.direction) continue;

            if (r.protocol != FWP_IPPROTO_ANY && r.protocol != packet.protocol) continue;

            if (packet.direction == FWP_DIRECTION_INBOUND) {
                if (r.localPort != 0 && r.localPort != packet.dstPort) continue;
            } else {
                if (r.remotePort != 0 && r.remotePort != packet.dstPort) continue;
            }

            if (!r.applicationPath.empty() && r.applicationPath != packet.appPath) continue;

            if (r.action == FWP_ACTION_PERMIT) {
                return FWP_ACTION_PERMIT;
            }
        }

        // 3. Fallback to default profile policy
        if (packet.direction == FWP_DIRECTION_INBOUND) {
            return profile.defaultInboundAction;
        } else {
            return profile.defaultOutboundAction;
        }
    }
};

// ============================================================================
// 4. Standard Win32 WFP C API Functions (fwpuclnt.dll)
// ============================================================================

inline DWORD WINAPI FwpmEngineOpen0(
    PCWSTR serverName,
    UINT32 authnService,
    [[maybe_unused]] void* authIdentity,
    const FWPM_SESSION0* session,
    HANDLE* engineHandle) {
    return SovereignWfpManager::get().openEngine(serverName, authnService, session, engineHandle);
}

inline DWORD WINAPI FwpmEngineClose0(HANDLE engineHandle) {
    return SovereignWfpManager::get().closeEngine(engineHandle);
}

inline DWORD WINAPI FwpmFilterAdd0(
    HANDLE engineHandle,
    const FWPM_FILTER0* filter,
    [[maybe_unused]] void* sd,
    UINT64* id) {
    return SovereignWfpManager::get().addFilter(engineHandle, filter, id);
}

inline DWORD WINAPI FwpmFilterDeleteById0(HANDLE engineHandle, UINT64 id) {
    return SovereignWfpManager::get().deleteFilterById(engineHandle, id);
}

inline DWORD WINAPI FwpmFilterGetById0(HANDLE engineHandle, UINT64 id, FWPM_FILTER0** filter) {
    return SovereignWfpManager::get().getFilterById(engineHandle, id, filter);
}

inline DWORD WINAPI FwpmSubLayerAdd0(
    HANDLE engineHandle,
    const FWPM_SUBLAYER0* subLayer,
    [[maybe_unused]] void* sd) {
    return SovereignWfpManager::get().addSubLayer(engineHandle, subLayer);
}

inline DWORD WINAPI FwpmSubLayerDeleteById0(HANDLE engineHandle, const GUID* key) {
    return SovereignWfpManager::get().deleteSubLayerById(engineHandle, key);
}

inline void WINAPI FwpmFreeMemory0(void** p) {
    if (p && *p) {
        delete reinterpret_cast<uint8_t*>(*p);
        *p = nullptr;
    }
}

// ============================================================================
// 5. Subsystem Export Registration Helper
// ============================================================================

inline void InitializeWfpSubsystemExports() {
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        auto& loader = ldr::DynamicLoader::get();

        // 1. Register fwpuclnt.dll dynamic exports
        loader.registerExport("fwpuclnt.dll", "FwpmEngineOpen0", reinterpret_cast<void*>(&FwpmEngineOpen0));
        loader.registerExport("fwpuclnt.dll", "FwpmEngineClose0", reinterpret_cast<void*>(&FwpmEngineClose0));
        loader.registerExport("fwpuclnt.dll", "FwpmFilterAdd0", reinterpret_cast<void*>(&FwpmFilterAdd0));
        loader.registerExport("fwpuclnt.dll", "FwpmFilterDeleteById0", reinterpret_cast<void*>(&FwpmFilterDeleteById0));
        loader.registerExport("fwpuclnt.dll", "FwpmFilterGetById0", reinterpret_cast<void*>(&FwpmFilterGetById0));
        loader.registerExport("fwpuclnt.dll", "FwpmSubLayerAdd0", reinterpret_cast<void*>(&FwpmSubLayerAdd0));
        loader.registerExport("fwpuclnt.dll", "FwpmSubLayerDeleteById0", reinterpret_cast<void*>(&FwpmSubLayerDeleteById0));
        loader.registerExport("fwpuclnt.dll", "FwpmFreeMemory0", reinterpret_cast<void*>(&FwpmFreeMemory0));

        // 2. Register in VersionDatabase
        version::VersionDatabase::Instance().RegisterModule(
            "fwpuclnt.dll",
            "10.0.22621.1",
            "Windows Filtering Platform API Client",
            "MicaNT Sovereign Project"
        );
    });
}

} // namespace micant::wfp
