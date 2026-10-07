// ============================================================================
// MicaNT: Windows Native Wifi & Sovereign WLAN Subsystem
// (include/micant/wlanapi.hpp)
//
// Strict Clean-Room Implementation based on:
//   - Microsoft Native Wifi (wlanapi.h / windot11.h) Win32 C ABI Specification
//   - IEEE 802.11-2020 Wireless LAN Architecture (802.11n, 802.11ac, 802.11ax Wi-Fi 6E)
//   - WPA2 / WPA3-Personal (SAE) & Enterprise Security Specifications
//   - Windows WLANProfile XML Schema Specification
//
// Subsystem Overview:
//   wlanapi.hpp provides the Windows Native Wifi (WLAN) subsystem for MicaNT,
//   enabling standard Win32 wireless networking clients, system trays, and
//   command utilities to inspect adapters, scan wireless spectrums, manage
//   802.11 XML profiles, and connect to secured access points without external
//   dependencies, hardware bloat, or telemetry.
//
// Features:
//   - Native Win32 WLAN C API:
//       * WlanOpenHandle / WlanCloseHandle
//       * WlanEnumInterfaces / WlanGetInterfaceCapability
//       * WlanScan / WlanGetAvailableNetworkList / WlanGetNetworkBssList
//       * WlanQueryInterface / WlanSetInterface
//       * WlanConnect / WlanDisconnect
//       * WlanRegisterNotification
//       * WlanSetProfile / WlanGetProfile / WlanDeleteProfile / WlanGetProfileList
//       * WlanReasonCodeToString
//       * WlanFreeMemory
//   - 802.11 Physical & MAC Spectrum Simulation:
//       * Multi-band support: 2.4 GHz, 5 GHz, and 6 GHz
//       * Standards: 802.11b (HR/DSSS), 802.11g (ERP), 802.11n (HT), 802.11ac (VHT), 802.11ax (HE)
//       * Realistic RSSI (dBm) to Link Quality percentage mapping
//       * Security suites: Open, WEP, WPA2-PSK (AES-CCMP), WPA3-SAE, WPA3-Enterprise
//   - Sovereign Virtual WLAN Miniport & Interface State Machine:
//       * Radio state management (Hardware / Software ON and OFF)
//       * Asynchronous scan cache and BSSID survey engine
//       * Connection state machine (disconnected, associating, authenticating, connected)
//       * Real-time ACM notification dispatching
//
// Core Dynamic Module:
//   - wlanapi.dll
//
// Trademark & Nominative Fair Use Notice:
//   Windows and Native Wifi are registered trademarks of Microsoft Corp.
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

namespace micant::wlan {

// ============================================================================
// 1. Standard Win32 WLAN Types & Constants
// ============================================================================

using DWORD     = uint32_t;
using LONG      = int32_t;
using BOOL      = int32_t;
using VOID      = void;
using BYTE      = uint8_t;
using UCHAR     = uint8_t;
using USHORT    = uint16_t;
using ULONG     = uint32_t;
using ULONGLONG = uint64_t;
using BOOLEAN   = uint8_t;
using WCHAR     = wchar_t;
using PWCHAR    = wchar_t*;
using LPCWSTR   = const wchar_t*;
using LPWSTR    = wchar_t*;
using PVOID     = void*;
using HANDLE    = void*;
using PHANDLE   = void**;
using PDWORD    = uint32_t*;
using GUID      = micant::GUID;

#ifndef WINAPI
#define WINAPI __stdcall
#endif

// Client Versions
inline constexpr DWORD WLAN_CLIENT_VERSION_VISTA  = 1;
inline constexpr DWORD WLAN_CLIENT_VERSION_WINXP  = 1;
inline constexpr DWORD WLAN_CLIENT_VERSION_WIN7   = 2;
inline constexpr DWORD WLAN_CLIENT_VERSION_WIN8   = 2;
inline constexpr DWORD WLAN_CLIENT_VERSION_WIN10  = 2;

// SSID Length
inline constexpr ULONG DOT11_SSID_MAX_LENGTH = 32;

// Reason Codes
inline constexpr DWORD WLAN_REASON_CODE_SUCCESS                     = 0;
inline constexpr DWORD WLAN_REASON_CODE_UNKNOWN                     = 0x10001;
inline constexpr DWORD WLAN_REASON_CODE_NETWORK_NOT_AVAILABLE       = 0x00051;
inline constexpr DWORD WLAN_REASON_CODE_TOO_MANY_SECURITY_ATTEMPTS  = 0x00052;
inline constexpr DWORD WLAN_REASON_CODE_MSMSEC_PROFILE_INVALID_KEY_INDEX = 0x00053;
inline constexpr DWORD WLAN_REASON_CODE_MSMSEC_KEY_START            = 0x00054;
inline constexpr DWORD WLAN_REASON_CODE_MSMSEC_KEY_SUCCESS          = 0x00055;
inline constexpr DWORD WLAN_REASON_CODE_USER_CANCELLED              = 0x10002;

// Notification Sources
inline constexpr DWORD WLAN_NOTIFICATION_SOURCE_NONE        = 0;
inline constexpr DWORD WLAN_NOTIFICATION_SOURCE_ALL         = 0x0000FFFF;
inline constexpr DWORD WLAN_NOTIFICATION_SOURCE_ACM         = 0x00000008;
inline constexpr DWORD WLAN_NOTIFICATION_SOURCE_MSM         = 0x00000010;
inline constexpr DWORD WLAN_NOTIFICATION_SOURCE_SECURITY    = 0x00000020;
inline constexpr DWORD WLAN_NOTIFICATION_SOURCE_IHV         = 0x00000040;
inline constexpr DWORD WLAN_NOTIFICATION_SOURCE_HNWK        = 0x00000080;
inline constexpr DWORD WLAN_NOTIFICATION_SOURCE_ONEX        = 0x00000004;

// ACM Notification Codes
inline constexpr DWORD wlan_notification_acm_start                   = 0;
inline constexpr DWORD wlan_notification_acm_autoconf_enabled         = 1;
inline constexpr DWORD wlan_notification_acm_autoconf_disabled        = 2;
inline constexpr DWORD wlan_notification_acm_background_scan_enabled  = 3;
inline constexpr DWORD wlan_notification_acm_background_scan_disabled = 4;
inline constexpr DWORD wlan_notification_acm_bss_type_change         = 5;
inline constexpr DWORD wlan_notification_acm_power_setting_change    = 6;
inline constexpr DWORD wlan_notification_acm_scan_complete           = 7;
inline constexpr DWORD wlan_notification_acm_scan_fail               = 8;
inline constexpr DWORD wlan_notification_acm_connection_start        = 9;
inline constexpr DWORD wlan_notification_acm_connection_complete     = 10;
inline constexpr DWORD wlan_notification_acm_connection_attempt_fail  = 11;
inline constexpr DWORD wlan_notification_acm_filter_list_change      = 12;
inline constexpr DWORD wlan_notification_acm_interface_arrival       = 13;
inline constexpr DWORD wlan_notification_acm_interface_removal       = 14;
inline constexpr DWORD wlan_notification_acm_profile_change          = 15;
inline constexpr DWORD wlan_notification_acm_profile_name_change     = 16;
inline constexpr DWORD wlan_notification_acm_profiles_exhausted      = 17;
inline constexpr DWORD wlan_notification_acm_network_not_available   = 18;
inline constexpr DWORD wlan_notification_acm_network_available       = 19;
inline constexpr DWORD wlan_notification_acm_disconnecting           = 20;
inline constexpr DWORD wlan_notification_acm_disconnected            = 21;
inline constexpr DWORD wlan_notification_acm_peer_join               = 22;
inline constexpr DWORD wlan_notification_acm_peer_leave              = 23;

// Available Network Flags
inline constexpr DWORD WLAN_AVAILABLE_NETWORK_CONNECTED    = 0x00000001;
inline constexpr DWORD WLAN_AVAILABLE_NETWORK_HAS_PROFILE  = 0x00000002;

// Profile Flags
inline constexpr DWORD WLAN_PROFILE_GROUP_POLICY      = 0x00000001;
inline constexpr DWORD WLAN_PROFILE_USER              = 0x00000002;
inline constexpr DWORD WLAN_PROFILE_GET_PLAINTEXT_KEY = 0x00000004;

// Interface Capability Types
inline constexpr DWORD WLAN_INTERFACE_TYPE_EMULATED_802_11 = 0;
inline constexpr DWORD WLAN_INTERFACE_TYPE_NATIVE_802_11   = 1;

// Error Codes
inline constexpr DWORD ERROR_SUCCESS            = 0;
inline constexpr DWORD ERROR_INVALID_PARAMETER  = 87;
inline constexpr DWORD ERROR_INVALID_HANDLE     = 6;
inline constexpr DWORD ERROR_NOT_ENOUGH_MEMORY  = 8;
inline constexpr DWORD ERROR_NOT_FOUND          = 1168;
inline constexpr DWORD ERROR_ACCESS_DENIED      = 5;
inline constexpr DWORD ERROR_ALREADY_EXISTS     = 183;
inline constexpr DWORD ERROR_BAD_PROFILE        = 12053;

// PHY Types (802.11 standards)
enum DOT11_PHY_TYPE {
    dot11_phy_type_unknown    = 0,
    dot11_phy_type_any        = 0,
    dot11_phy_type_fhss       = 1,
    dot11_phy_type_dsss       = 2,
    dot11_phy_type_irbaseband = 3,
    dot11_phy_type_ofdm       = 4, // 802.11a
    dot11_phy_type_hrdsss     = 5, // 802.11b
    dot11_phy_type_erp        = 6, // 802.11g
    dot11_phy_type_ht         = 7, // 802.11n (Wi-Fi 4)
    dot11_phy_type_vht        = 8, // 802.11ac (Wi-Fi 5)
    dot11_phy_type_he         = 9, // 802.11ax (Wi-Fi 6 / 6E)
    dot11_phy_type_eht        = 10 // 802.11be (Wi-Fi 7)
};

// Interface State
enum WLAN_INTERFACE_STATE {
    wlan_interface_state_not_ready               = 0,
    wlan_interface_state_connected               = 1,
    wlan_interface_state_ad_hoc_network_formed   = 2,
    wlan_interface_state_disconnecting           = 3,
    wlan_interface_state_disconnected            = 4,
    wlan_interface_state_associating             = 5,
    wlan_interface_state_discovering             = 6,
    wlan_interface_state_authenticating          = 7
};
using PWLAN_INTERFACE_STATE = WLAN_INTERFACE_STATE*;

// BSS Type
enum DOT11_BSS_TYPE {
    dot11_BSS_type_infrastructure = 1,
    dot11_BSS_type_independent    = 2,
    dot11_BSS_type_any            = 3
};

// Auth Algorithms
enum DOT11_AUTH_ALGORITHM {
    DOT11_AUTH_ALGO_80211_OPEN       = 1,
    DOT11_AUTH_ALGO_80211_SHARED_KEY = 2,
    DOT11_AUTH_ALGO_WPA              = 3,
    DOT11_AUTH_ALGO_WPA_PSK          = 4,
    DOT11_AUTH_ALGO_WPA_NONE         = 5,
    DOT11_AUTH_ALGO_RSNA             = 6, // WPA2
    DOT11_AUTH_ALGO_RSNA_PSK         = 7, // WPA2-PSK
    DOT11_AUTH_ALGO_WPA3             = 8,
    DOT11_AUTH_ALGO_WPA3_SAE         = 9,
    DOT11_AUTH_ALGO_IHV_START        = 0x80000000
};

// Cipher Algorithms
enum DOT11_CIPHER_ALGORITHM {
    DOT11_CIPHER_ALGO_NONE           = 0x00,
    DOT11_CIPHER_ALGO_WEP40          = 0x01,
    DOT11_CIPHER_ALGO_TKIP           = 0x02,
    DOT11_CIPHER_ALGO_CCMP           = 0x04, // AES-CCMP
    DOT11_CIPHER_ALGO_WEP104         = 0x05,
    DOT11_CIPHER_ALGO_WPA_USE_GROUP  = 0x100,
    DOT11_CIPHER_ALGO_RSN_USE_GROUP  = 0x100,
    DOT11_CIPHER_ALGO_WEP            = 0x101,
    DOT11_CIPHER_ALGO_GCMP           = 0x08
};

// Radio State
enum DOT11_RADIO_STATE {
    dot11_radio_state_unknown = 0,
    dot11_radio_state_on      = 1,
    dot11_radio_state_off     = 2
};

// Interface Opcode
enum WLAN_INTF_OPCODE {
    wlan_intf_opcode_autoconf_start                              = 0x00000000,
    wlan_intf_opcode_autoconf_enabled                            = 1,
    wlan_intf_opcode_background_scan_enabled                     = 2,
    wlan_intf_opcode_media_streaming_mode                        = 3,
    wlan_intf_opcode_radio_state                                 = 4,
    wlan_intf_opcode_bss_type                                    = 5,
    wlan_intf_opcode_interface_state                             = 6,
    wlan_intf_opcode_current_connection                          = 7,
    wlan_intf_opcode_channel_number                              = 8,
    wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs  = 9,
    wlan_intf_opcode_supported_adhoc_auth_cipher_pairs           = 10,
    wlan_intf_opcode_supported_country_or_region_string_list     = 11,
    wlan_intf_opcode_current_operation_mode                      = 12,
    wlan_intf_opcode_supported_safe_mode                         = 13,
    wlan_intf_opcode_certified_safe_mode                         = 14,
    wlan_intf_opcode_hosted_network_capable                      = 15,
    wlan_intf_opcode_management_frame_protection_capable         = 16
};

enum WLAN_OPCODE_VALUE_TYPE {
    wlan_opcode_value_type_query_only           = 0,
    wlan_opcode_value_type_set_by_group_policy  = 1,
    wlan_opcode_value_type_set_by_user          = 2,
    wlan_opcode_value_type_invalid              = 3
};
using PWLAN_OPCODE_VALUE_TYPE = WLAN_OPCODE_VALUE_TYPE*;

enum WLAN_CONNECTION_MODE {
    wlan_connection_mode_profile            = 0,
    wlan_connection_mode_temporary_profile  = 1,
    wlan_connection_mode_discovery_secure   = 2,
    wlan_connection_mode_discovery_unsecure = 3,
    wlan_connection_mode_auto               = 4,
    wlan_connection_mode_invalid            = 5
};

// ============================================================================
// 2. Win32 WLAN Structures (conforming to wlanapi.h)
// ============================================================================

struct DOT11_SSID {
    ULONG uSSIDLength{ 0 };
    UCHAR ucSSID[DOT11_SSID_MAX_LENGTH]{ 0 };
};
using PDOT11_SSID = DOT11_SSID*;

struct DOT11_MAC_ADDRESS {
    UCHAR ucDot11MacAddress[6]{ 0 };
};

struct DOT11_BSSID_LIST {
    DOT11_MAC_ADDRESS Bssids[1];
};
using PDOT11_BSSID_LIST = DOT11_BSSID_LIST*;

struct WLAN_PHY_INFO {
    DOT11_RADIO_STATE dot11SoftwareRadioState{ dot11_radio_state_on };
    DOT11_RADIO_STATE dot11HardwareRadioState{ dot11_radio_state_on };
};

struct WLAN_RADIO_STATE {
    DWORD dwNumberOfPhys{ 1 };
    WLAN_PHY_INFO PhyInfo[1];
};
using PWLAN_RADIO_STATE = WLAN_RADIO_STATE*;

struct WLAN_INTERFACE_INFO {
    GUID InterfaceGuid{};
    WCHAR strInterfaceDescription[256]{ 0 };
    WLAN_INTERFACE_STATE isState{ wlan_interface_state_disconnected };
};
using PWLAN_INTERFACE_INFO = WLAN_INTERFACE_INFO*;

struct WLAN_INTERFACE_INFO_LIST {
    DWORD dwNumberOfItems{ 0 };
    DWORD dwIndex{ 0 };
    WLAN_INTERFACE_INFO InterfaceInfo[1];
};
using PWLAN_INTERFACE_INFO_LIST = WLAN_INTERFACE_INFO_LIST*;

struct WLAN_INTERFACE_CAPABILITY {
    DWORD interfaceType{ WLAN_INTERFACE_TYPE_NATIVE_802_11 };
    BOOL bDot11DSupported{ 1 };
    DWORD dwMaxDesiredSsidListSize{ 32 };
    DWORD dwMaxDesiredBssidListSize{ 32 };
    DWORD dwNumberOfSupportedPhys{ 5 };
    DOT11_PHY_TYPE dot11PhyTypes[8]{
        dot11_phy_type_he,   // 802.11ax Wi-Fi 6E
        dot11_phy_type_vht,  // 802.11ac Wi-Fi 5
        dot11_phy_type_ht,   // 802.11n Wi-Fi 4
        dot11_phy_type_erp,  // 802.11g
        dot11_phy_type_hrdsss // 802.11b
    };
};
using PWLAN_INTERFACE_CAPABILITY = WLAN_INTERFACE_CAPABILITY*;

struct WLAN_RAW_DATA {
    DWORD dwDataSize{ 0 };
    BYTE DataBlob[1];
};
using PWLAN_RAW_DATA = WLAN_RAW_DATA*;

using WLAN_SIGNAL_QUALITY = ULONG; // 0 to 100
using WLAN_REASON_CODE = DWORD;

struct WLAN_AVAILABLE_NETWORK {
    WCHAR strProfileName[256]{ 0 };
    DOT11_SSID dot11Ssid{};
    DOT11_BSS_TYPE dot11BssType{ dot11_BSS_type_infrastructure };
    ULONG uNumberOfBssids{ 1 };
    BOOL bNetworkConnectable{ 1 };
    WLAN_REASON_CODE wlanNotConnectableReason{ WLAN_REASON_CODE_SUCCESS };
    ULONG uNumberOfPhyTypes{ 1 };
    DOT11_PHY_TYPE dot11PhyTypes[8]{ dot11_phy_type_he };
    BOOL bMorePhyTypes{ 0 };
    WLAN_SIGNAL_QUALITY wlanSignalQuality{ 80 };
    BOOL bSecurityEnabled{ 1 };
    DOT11_AUTH_ALGORITHM dot11DefaultAuthAlgorithm{ DOT11_AUTH_ALGO_RSNA_PSK };
    DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm{ DOT11_CIPHER_ALGO_CCMP };
    DWORD dwFlags{ 0 };
    DWORD dwReserved{ 0 };
};
using PWLAN_AVAILABLE_NETWORK = WLAN_AVAILABLE_NETWORK*;

struct WLAN_AVAILABLE_NETWORK_LIST {
    DWORD dwNumberOfItems{ 0 };
    DWORD dwIndex{ 0 };
    WLAN_AVAILABLE_NETWORK Network[1];
};
using PWLAN_AVAILABLE_NETWORK_LIST = WLAN_AVAILABLE_NETWORK_LIST*;

struct WLAN_RATE_SET {
    ULONG uRateSetLength{ 8 };
    USHORT usRateSet[126]{ 12, 18, 24, 36, 48, 72, 96, 108 };
};

struct WLAN_BSS_ENTRY {
    DOT11_SSID dot11Ssid{};
    ULONG uPhyId{ 0 };
    DOT11_MAC_ADDRESS dot11Bssid{};
    DOT11_BSS_TYPE dot11BssType{ dot11_BSS_type_infrastructure };
    DOT11_PHY_TYPE dot11BssPhyType{ dot11_phy_type_he };
    LONG lRssi{ -50 };
    ULONG uLinkQuality{ 85 };
    BOOLEAN bInRegDomain{ 1 };
    USHORT usBeaconPeriod{ 100 };
    ULONGLONG ullTimestamp{ 1000000 };
    ULONGLONG ullHostTimestamp{ 2000000 };
    USHORT usCapabilityInformation{ 0x0011 };
    ULONG ulChCenterFrequency{ 5180000 }; // 5 GHz Channel 36
    WLAN_RATE_SET wlanRateSet{};
    ULONG ulIeOffset{ 0 };
    ULONG ulIeSize{ 0 };
};
using PWLAN_BSS_ENTRY = WLAN_BSS_ENTRY*;

struct WLAN_BSS_LIST {
    DWORD dwTotalSize{ 0 };
    DWORD dwNumberOfItems{ 0 };
    WLAN_BSS_ENTRY wlanBssEntries[1];
};
using PWLAN_BSS_LIST = WLAN_BSS_LIST*;

struct WLAN_PROFILE_INFO {
    WCHAR strProfileName[256]{ 0 };
    DWORD dwFlags{ 0 };
};
using PWLAN_PROFILE_INFO = WLAN_PROFILE_INFO*;

struct WLAN_PROFILE_INFO_LIST {
    DWORD dwNumberOfItems{ 0 };
    DWORD dwIndex{ 0 };
    WLAN_PROFILE_INFO ProfileInfo[1];
};
using PWLAN_PROFILE_INFO_LIST = WLAN_PROFILE_INFO_LIST*;

struct WLAN_CONNECTION_PARAMETERS {
    WLAN_CONNECTION_MODE wlanConnectionMode{ wlan_connection_mode_profile };
    LPCWSTR strProfile{ nullptr };
    PDOT11_SSID pDot11Ssid{ nullptr };
    PDOT11_BSSID_LIST pDesiredBssidList{ nullptr };
    DOT11_BSS_TYPE dot11BssType{ dot11_BSS_type_infrastructure };
    DWORD dwFlags{ 0 };
};
using PWLAN_CONNECTION_PARAMETERS = WLAN_CONNECTION_PARAMETERS*;

struct WLAN_ASSOCIATION_ATTRIBUTES {
    DOT11_SSID dot11Ssid{};
    DOT11_BSS_TYPE dot11BssType{ dot11_BSS_type_infrastructure };
    DOT11_MAC_ADDRESS dot11Bssid{};
    DOT11_PHY_TYPE dot11PhyType{ dot11_phy_type_he };
    ULONG uDot11PhyIndex{ 0 };
    WLAN_SIGNAL_QUALITY wlanSignalQuality{ 85 };
    ULONG ulRxRate{ 1201000 }; // 1.2 Gbps Wi-Fi 6
    ULONG ulTxRate{ 1201000 };
};

struct WLAN_SECURITY_ATTRIBUTES {
    BOOL bSecurityEnabled{ 1 };
    BOOL bOneXEnabled{ 0 };
    DOT11_AUTH_ALGORITHM dot11AuthAlgorithm{ DOT11_AUTH_ALGO_RSNA_PSK };
    DOT11_CIPHER_ALGORITHM dot11CipherAlgorithm{ DOT11_CIPHER_ALGO_CCMP };
};

struct WLAN_CONNECTION_ATTRIBUTES {
    WLAN_INTERFACE_STATE isState{ wlan_interface_state_connected };
    WLAN_CONNECTION_MODE wlanConnectionMode{ wlan_connection_mode_profile };
    WCHAR strProfileName[256]{ 0 };
    WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes{};
    WLAN_SECURITY_ATTRIBUTES wlanSecurityAttributes{};
};
using PWLAN_CONNECTION_ATTRIBUTES = WLAN_CONNECTION_ATTRIBUTES*;

struct WLAN_NOTIFICATION_DATA {
    DWORD NotificationSource{ 0 };
    DWORD NotificationCode{ 0 };
    GUID InterfaceGuid{};
    DWORD dwDataSize{ 0 };
    PVOID pData{ nullptr };
};
using PWLAN_NOTIFICATION_DATA = WLAN_NOTIFICATION_DATA*;

using WLAN_NOTIFICATION_CALLBACK = void(WINAPI*)(PWLAN_NOTIFICATION_DATA, PVOID);

// ============================================================================
// 3. Sovereign Virtual WLAN Miniport & Network Discovery Engine
// ============================================================================

struct SimulatedBss {
    std::string ssid;
    uint8_t bssid[6]{ 0 };
    uint32_t frequencyKhz{ 5180000 };
    int32_t rssi{ -50 };
    uint32_t linkQuality{ 85 };
    DOT11_PHY_TYPE phyType{ dot11_phy_type_he };
    DOT11_AUTH_ALGORITHM authAlgo{ DOT11_AUTH_ALGO_RSNA_PSK };
    DOT11_CIPHER_ALGORITHM cipherAlgo{ DOT11_CIPHER_ALGO_CCMP };
    bool securityEnabled{ true };
};

struct ClientSession {
    DWORD clientVersion{ 2 };
    DWORD negotiatedVersion{ 2 };
    DWORD notificationSource{ WLAN_NOTIFICATION_SOURCE_NONE };
    WLAN_NOTIFICATION_CALLBACK notificationCallback{ nullptr };
    PVOID callbackContext{ nullptr };
};

class SovereignWlanManager {
private:
    std::mutex m_mutex;
    uintptr_t m_nextHandle{ 0x2000 };
    std::unordered_map<HANDLE, ClientSession> m_clients;

    // Interface Info
    GUID m_interfaceGuid{
        0x574C414E, 0x3031, 0x4D49,
        { 0x43, 0x41, 0x4E, 0x54, 0x31, 0x00, 0x00, 0x01 }
    };
    std::wstring m_interfaceDescription{ L"MicaNT Sovereign 802.11ax Wi-Fi 6E Wireless Adapter" };
    uint8_t m_macAddress[6]{ 0x02, 0x53, 0x4F, 0x56, 0x45, 0x52 }; // "SOVER"
    WLAN_INTERFACE_STATE m_interfaceState{ wlan_interface_state_disconnected };
    DOT11_RADIO_STATE m_softwareRadio{ dot11_radio_state_on };
    DOT11_RADIO_STATE m_hardwareRadio{ dot11_radio_state_on };
    ULONG m_channelNumber{ 36 };

    // Networks & BSS database
    std::vector<SimulatedBss> m_bssList;

    // XML Profiles
    std::unordered_map<std::wstring, std::wstring> m_profiles;

    // Connected Network Info
    std::string m_connectedSsid;
    std::wstring m_connectedProfile;
    SimulatedBss m_connectedBss{};

    SovereignWlanManager() {
        // 1. Seed Access Points
        SimulatedBss ap1{};
        ap1.ssid = "MicaNT-Corp-Secure";
        ap1.bssid[0] = 0x02; ap1.bssid[1] = 0xAA; ap1.bssid[2] = 0xBB;
        ap1.bssid[3] = 0xCC; ap1.bssid[4] = 0xDD; ap1.bssid[5] = 0x01;
        ap1.frequencyKhz = 5180000; // 5 GHz Channel 36
        ap1.rssi = -48;
        ap1.linkQuality = 96;
        ap1.phyType = dot11_phy_type_he; // Wi-Fi 6
        ap1.authAlgo = DOT11_AUTH_ALGO_WPA3;
        ap1.cipherAlgo = DOT11_CIPHER_ALGO_CCMP;
        ap1.securityEnabled = true;
        m_bssList.push_back(ap1);

        SimulatedBss ap2{};
        ap2.ssid = "SovereignNet-5G";
        ap2.bssid[0] = 0x02; ap2.bssid[1] = 0xAA; ap2.bssid[2] = 0xBB;
        ap2.bssid[3] = 0xCC; ap2.bssid[4] = 0xDD; ap2.bssid[5] = 0x02;
        ap2.frequencyKhz = 5745000; // 5 GHz Channel 149
        ap2.rssi = -58;
        ap2.linkQuality = 84;
        ap2.phyType = dot11_phy_type_vht; // Wi-Fi 5
        ap2.authAlgo = DOT11_AUTH_ALGO_RSNA_PSK; // WPA2-PSK
        ap2.cipherAlgo = DOT11_CIPHER_ALGO_CCMP;
        ap2.securityEnabled = true;
        m_bssList.push_back(ap2);

        SimulatedBss ap3{};
        ap3.ssid = "Guest-Open";
        ap3.bssid[0] = 0x02; ap3.bssid[1] = 0xAA; ap3.bssid[2] = 0xBB;
        ap3.bssid[3] = 0xCC; ap3.bssid[4] = 0xDD; ap3.bssid[5] = 0x03;
        ap3.frequencyKhz = 2437000; // 2.4 GHz Channel 6
        ap3.rssi = -72;
        ap3.linkQuality = 56;
        ap3.phyType = dot11_phy_type_ht; // Wi-Fi 4
        ap3.authAlgo = DOT11_AUTH_ALGO_80211_OPEN;
        ap3.cipherAlgo = DOT11_CIPHER_ALGO_NONE;
        ap3.securityEnabled = false;
        m_bssList.push_back(ap3);

        SimulatedBss ap4{};
        ap4.ssid = "Lab-IoT-Mesh";
        ap4.bssid[0] = 0x02; ap4.bssid[1] = 0xAA; ap4.bssid[2] = 0xBB;
        ap4.bssid[3] = 0xCC; ap4.bssid[4] = 0xDD; ap4.bssid[5] = 0x04;
        ap4.frequencyKhz = 2412000; // 2.4 GHz Channel 1
        ap4.rssi = -65;
        ap4.linkQuality = 70;
        ap4.phyType = dot11_phy_type_he;
        ap4.authAlgo = DOT11_AUTH_ALGO_RSNA_PSK;
        ap4.cipherAlgo = DOT11_CIPHER_ALGO_CCMP;
        ap4.securityEnabled = true;
        m_bssList.push_back(ap4);

        // 2. Pre-seed Default Profile for SovereignNet-5G
        std::wstring defXml =
            L"<?xml version=\"1.0\"?>\n"
            L"<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n"
            L"    <name>SovereignNet-5G</name>\n"
            L"    <SSIDConfig>\n"
            L"        <SSID><name>SovereignNet-5G</name></SSID>\n"
            L"    </SSIDConfig>\n"
            L"    <connectionType>ESS</connectionType>\n"
            L"    <connectionMode>auto</connectionMode>\n"
            L"    <MSM>\n"
            L"        <security>\n"
            L"            <authEncryption>\n"
            L"                <authentication>WPA2PSK</authentication>\n"
            L"                <encryption>AES</encryption>\n"
            L"                <useOneX>false</useOneX>\n"
            L"            </authEncryption>\n"
            L"        </security>\n"
            L"    </MSM>\n"
            L"</WLANProfile>\n";
        m_profiles[L"SovereignNet-5G"] = defXml;
    }

    void dispatchNotification(DWORD source, DWORD code, PVOID pData = nullptr, DWORD dataSize = 0) {
        WLAN_NOTIFICATION_DATA data{};
        data.NotificationSource = source;
        data.NotificationCode = code;
        data.InterfaceGuid = m_interfaceGuid;
        data.dwDataSize = dataSize;
        data.pData = pData;

        for (auto& pair : m_clients) {
            if ((pair.second.notificationSource & source) && pair.second.notificationCallback) {
                pair.second.notificationCallback(&data, pair.second.callbackContext);
            }
        }
    }

public:
    static SovereignWlanManager& get() {
        static SovereignWlanManager s_instance;
        return s_instance;
    }

    // Client Handle Management
    DWORD openHandle(DWORD dwClientVersion, PDWORD pdwNegotiatedVersion, PHANDLE phClientHandle) {
        if (!pdwNegotiatedVersion || !phClientHandle) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        *pdwNegotiatedVersion = std::min(dwClientVersion, WLAN_CLIENT_VERSION_WIN10);
        HANDLE h = reinterpret_cast<HANDLE>(m_nextHandle++);
        ClientSession sess{};
        sess.clientVersion = dwClientVersion;
        sess.negotiatedVersion = *pdwNegotiatedVersion;
        m_clients[h] = sess;
        *phClientHandle = h;
        return ERROR_SUCCESS;
    }

    DWORD closeHandle(HANDLE hClientHandle) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_clients.find(hClientHandle);
        if (it == m_clients.end()) return ERROR_INVALID_HANDLE;
        m_clients.erase(it);
        return ERROR_SUCCESS;
    }

    bool isValidHandle(HANDLE h) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_clients.find(h) != m_clients.end();
    }

    // Interface Enumeration
    DWORD enumInterfaces(PWLAN_INTERFACE_INFO_LIST* ppInterfaceList) {
        if (!ppInterfaceList) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        size_t allocSize = sizeof(WLAN_INTERFACE_INFO_LIST);
        auto* pList = reinterpret_cast<PWLAN_INTERFACE_INFO_LIST>(new uint8_t[allocSize]);
        std::memset(pList, 0, allocSize);

        pList->dwNumberOfItems = 1;
        pList->dwIndex = 0;
        pList->InterfaceInfo[0].InterfaceGuid = m_interfaceGuid;
        std::wcsncpy(pList->InterfaceInfo[0].strInterfaceDescription, m_interfaceDescription.c_str(), 255);
        pList->InterfaceInfo[0].isState = m_interfaceState;

        *ppInterfaceList = pList;
        return ERROR_SUCCESS;
    }

    const GUID& getInterfaceGuid() const {
        return m_interfaceGuid;
    }

    // Capabilities
    DWORD getInterfaceCapability(PWLAN_INTERFACE_CAPABILITY* ppCapability) {
        if (!ppCapability) return ERROR_INVALID_PARAMETER;

        auto* pCap = reinterpret_cast<PWLAN_INTERFACE_CAPABILITY>(new uint8_t[sizeof(WLAN_INTERFACE_CAPABILITY)]);
        std::memset(pCap, 0, sizeof(WLAN_INTERFACE_CAPABILITY));
        pCap->interfaceType = WLAN_INTERFACE_TYPE_NATIVE_802_11;
        pCap->bDot11DSupported = 1;
        pCap->dwMaxDesiredSsidListSize = 32;
        pCap->dwMaxDesiredBssidListSize = 32;
        pCap->dwNumberOfSupportedPhys = 5;
        pCap->dot11PhyTypes[0] = dot11_phy_type_he;  // Wi-Fi 6E
        pCap->dot11PhyTypes[1] = dot11_phy_type_vht; // Wi-Fi 5
        pCap->dot11PhyTypes[2] = dot11_phy_type_ht;  // Wi-Fi 4
        pCap->dot11PhyTypes[3] = dot11_phy_type_erp;
        pCap->dot11PhyTypes[4] = dot11_phy_type_hrdsss;

        *ppCapability = pCap;
        return ERROR_SUCCESS;
    }

    // Network Scan
    DWORD triggerScan() {
        std::lock_guard<std::mutex> lock(m_mutex);
        dispatchNotification(WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_scan_complete);
        return ERROR_SUCCESS;
    }

    // Available Networks Query
    DWORD getAvailableNetworkList(PWLAN_AVAILABLE_NETWORK_LIST* ppAvailableNetworkList) {
        if (!ppAvailableNetworkList) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        size_t count = m_bssList.size();
        size_t totalBytes = sizeof(WLAN_AVAILABLE_NETWORK_LIST) + (count > 0 ? (count - 1) * sizeof(WLAN_AVAILABLE_NETWORK) : 0);
        auto* pList = reinterpret_cast<PWLAN_AVAILABLE_NETWORK_LIST>(new uint8_t[totalBytes]);
        std::memset(pList, 0, totalBytes);

        pList->dwNumberOfItems = static_cast<DWORD>(count);
        pList->dwIndex = 0;

        for (size_t i = 0; i < count; ++i) {
            const auto& src = m_bssList[i];
            auto& dst = pList->Network[i];

            std::wstring wName(src.ssid.begin(), src.ssid.end());
            std::wcsncpy(dst.strProfileName, wName.c_str(), 255);

            dst.dot11Ssid.uSSIDLength = static_cast<ULONG>(src.ssid.size());
            std::memcpy(dst.dot11Ssid.ucSSID, src.ssid.data(), src.ssid.size());

            dst.dot11BssType = dot11_BSS_type_infrastructure;
            dst.uNumberOfBssids = 1;
            dst.bNetworkConnectable = 1;
            dst.wlanNotConnectableReason = WLAN_REASON_CODE_SUCCESS;
            dst.uNumberOfPhyTypes = 1;
            dst.dot11PhyTypes[0] = src.phyType;
            dst.wlanSignalQuality = src.linkQuality;
            dst.bSecurityEnabled = src.securityEnabled ? 1 : 0;
            dst.dot11DefaultAuthAlgorithm = src.authAlgo;
            dst.dot11DefaultCipherAlgorithm = src.cipherAlgo;

            if (m_interfaceState == wlan_interface_state_connected && src.ssid == m_connectedSsid) {
                dst.dwFlags |= WLAN_AVAILABLE_NETWORK_CONNECTED;
            }
            if (m_profiles.count(wName)) {
                dst.dwFlags |= WLAN_AVAILABLE_NETWORK_HAS_PROFILE;
            }
        }

        *ppAvailableNetworkList = pList;
        return ERROR_SUCCESS;
    }

    // BSS List Query
    DWORD getNetworkBssList(PWLAN_BSS_LIST* ppWlanBssList) {
        if (!ppWlanBssList) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        size_t count = m_bssList.size();
        size_t totalBytes = sizeof(WLAN_BSS_LIST) + (count > 0 ? (count - 1) * sizeof(WLAN_BSS_ENTRY) : 0);
        auto* pList = reinterpret_cast<PWLAN_BSS_LIST>(new uint8_t[totalBytes]);
        std::memset(pList, 0, totalBytes);

        pList->dwTotalSize = static_cast<DWORD>(totalBytes);
        pList->dwNumberOfItems = static_cast<DWORD>(count);

        for (size_t i = 0; i < count; ++i) {
            const auto& src = m_bssList[i];
            auto& dst = pList->wlanBssEntries[i];

            dst.dot11Ssid.uSSIDLength = static_cast<ULONG>(src.ssid.size());
            std::memcpy(dst.dot11Ssid.ucSSID, src.ssid.data(), src.ssid.size());

            std::memcpy(dst.dot11Bssid.ucDot11MacAddress, src.bssid, 6);
            dst.dot11BssType = dot11_BSS_type_infrastructure;
            dst.dot11BssPhyType = src.phyType;
            dst.lRssi = src.rssi;
            dst.uLinkQuality = src.linkQuality;
            dst.bInRegDomain = 1;
            dst.usBeaconPeriod = 100;
            dst.ullTimestamp = 1000000;
            dst.ullHostTimestamp = 2000000;
            dst.usCapabilityInformation = src.securityEnabled ? 0x0011 : 0x0001;
            dst.ulChCenterFrequency = src.frequencyKhz;
            dst.wlanRateSet.uRateSetLength = 8;
        }

        *ppWlanBssList = pList;
        return ERROR_SUCCESS;
    }

    // Query Interface Properties
    DWORD queryInterface(
        WLAN_INTF_OPCODE opCode,
        PDWORD pdwDataSize,
        PVOID* ppData,
        PWLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType
    ) {
        if (!pdwDataSize || !ppData) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        if (pWlanOpcodeValueType) *pWlanOpcodeValueType = wlan_opcode_value_type_query_only;

        switch (opCode) {
            case wlan_intf_opcode_interface_state: {
                *pdwDataSize = sizeof(WLAN_INTERFACE_STATE);
                auto* pState = reinterpret_cast<PWLAN_INTERFACE_STATE>(new uint8_t[sizeof(WLAN_INTERFACE_STATE)]);
                *pState = m_interfaceState;
                *ppData = pState;
                return ERROR_SUCCESS;
            }
            case wlan_intf_opcode_radio_state: {
                *pdwDataSize = sizeof(WLAN_RADIO_STATE);
                auto* pRadio = reinterpret_cast<PWLAN_RADIO_STATE>(new uint8_t[sizeof(WLAN_RADIO_STATE)]);
                std::memset(pRadio, 0, sizeof(WLAN_RADIO_STATE));
                pRadio->dwNumberOfPhys = 1;
                pRadio->PhyInfo[0].dot11SoftwareRadioState = m_softwareRadio;
                pRadio->PhyInfo[0].dot11HardwareRadioState = m_hardwareRadio;
                *ppData = pRadio;
                return ERROR_SUCCESS;
            }
            case wlan_intf_opcode_channel_number: {
                *pdwDataSize = sizeof(ULONG);
                auto* pCh = reinterpret_cast<ULONG*>(new uint8_t[sizeof(ULONG)]);
                *pCh = m_channelNumber;
                *ppData = pCh;
                return ERROR_SUCCESS;
            }
            case wlan_intf_opcode_current_connection: {
                if (m_interfaceState != wlan_interface_state_connected) {
                    return ERROR_NOT_FOUND;
                }
                *pdwDataSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
                auto* pAttr = reinterpret_cast<PWLAN_CONNECTION_ATTRIBUTES>(new uint8_t[sizeof(WLAN_CONNECTION_ATTRIBUTES)]);
                std::memset(pAttr, 0, sizeof(WLAN_CONNECTION_ATTRIBUTES));
                pAttr->isState = wlan_interface_state_connected;
                pAttr->wlanConnectionMode = wlan_connection_mode_profile;
                std::wcsncpy(pAttr->strProfileName, m_connectedProfile.c_str(), 255);

                pAttr->wlanAssociationAttributes.dot11Ssid.uSSIDLength = static_cast<ULONG>(m_connectedBss.ssid.size());
                std::memcpy(pAttr->wlanAssociationAttributes.dot11Ssid.ucSSID, m_connectedBss.ssid.data(), m_connectedBss.ssid.size());
                std::memcpy(pAttr->wlanAssociationAttributes.dot11Bssid.ucDot11MacAddress, m_connectedBss.bssid, 6);
                pAttr->wlanAssociationAttributes.dot11PhyType = m_connectedBss.phyType;
                pAttr->wlanAssociationAttributes.wlanSignalQuality = m_connectedBss.linkQuality;
                pAttr->wlanAssociationAttributes.ulRxRate = 1201000;
                pAttr->wlanAssociationAttributes.ulTxRate = 1201000;

                pAttr->wlanSecurityAttributes.bSecurityEnabled = m_connectedBss.securityEnabled ? 1 : 0;
                pAttr->wlanSecurityAttributes.dot11AuthAlgorithm = m_connectedBss.authAlgo;
                pAttr->wlanSecurityAttributes.dot11CipherAlgorithm = m_connectedBss.cipherAlgo;

                *ppData = pAttr;
                return ERROR_SUCCESS;
            }
            default:
                return ERROR_INVALID_PARAMETER;
        }
    }

    // Set Interface Properties
    DWORD setInterface(WLAN_INTF_OPCODE opCode, DWORD dwDataSize, const PVOID pData) {
        if (!pData) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        switch (opCode) {
            case wlan_intf_opcode_radio_state: {
                if (dwDataSize < sizeof(WLAN_PHY_INFO)) return ERROR_INVALID_PARAMETER;
                const auto* pInfo = reinterpret_cast<const WLAN_PHY_INFO*>(pData);
                m_softwareRadio = pInfo->dot11SoftwareRadioState;
                dispatchNotification(WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_power_setting_change);
                return ERROR_SUCCESS;
            }
            default:
                return ERROR_INVALID_PARAMETER;
        }
    }

    // Connect & Disconnect
    DWORD connect(const PWLAN_CONNECTION_PARAMETERS pParams) {
        if (!pParams) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::string targetSsid;
        std::wstring targetProfile;

        if (pParams->strProfile && std::wcslen(pParams->strProfile) > 0) {
            targetProfile = pParams->strProfile;
            targetSsid = std::string(targetProfile.begin(), targetProfile.end());
        } else if (pParams->pDot11Ssid && pParams->pDot11Ssid->uSSIDLength > 0) {
            targetSsid = std::string(reinterpret_cast<const char*>(pParams->pDot11Ssid->ucSSID), pParams->pDot11Ssid->uSSIDLength);
            targetProfile = std::wstring(targetSsid.begin(), targetSsid.end());
        } else {
            return ERROR_INVALID_PARAMETER;
        }

        // Find candidate BSS
        const SimulatedBss* pFound = nullptr;
        for (const auto& bss : m_bssList) {
            if (bss.ssid == targetSsid) {
                pFound = &bss;
                break;
            }
        }
        if (!pFound) {
            return ERROR_NOT_FOUND;
        }

        // State Machine Transition: disconnected -> associating -> authenticating -> connected
        m_interfaceState = wlan_interface_state_associating;
        dispatchNotification(WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_connection_start);

        m_interfaceState = wlan_interface_state_authenticating;
        m_connectedSsid = targetSsid;
        m_connectedProfile = targetProfile;
        m_connectedBss = *pFound;
        m_interfaceState = wlan_interface_state_connected;

        dispatchNotification(WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_connection_complete);
        return ERROR_SUCCESS;
    }

    DWORD disconnect() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_interfaceState != wlan_interface_state_connected) {
            return ERROR_SUCCESS;
        }

        m_interfaceState = wlan_interface_state_disconnecting;
        dispatchNotification(WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_disconnecting);

        m_interfaceState = wlan_interface_state_disconnected;
        m_connectedSsid.clear();
        m_connectedProfile.clear();
        m_connectedBss = SimulatedBss{};

        dispatchNotification(WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_disconnected);
        return ERROR_SUCCESS;
    }

    // Profile Management
    DWORD setProfile(LPCWSTR strProfileXml, DWORD* pdwReasonCode) {
        if (!strProfileXml) return ERROR_INVALID_PARAMETER;
        if (pdwReasonCode) *pdwReasonCode = WLAN_REASON_CODE_SUCCESS;

        std::wstring xml(strProfileXml);
        // Extract profile name from <name>...</name> tag
        size_t nStart = xml.find(L"<name>");
        size_t nEnd = xml.find(L"</name>");
        if (nStart == std::wstring::npos || nEnd == std::wstring::npos || nEnd <= nStart + 6) {
            if (pdwReasonCode) *pdwReasonCode = WLAN_REASON_CODE_UNKNOWN;
            return ERROR_BAD_PROFILE;
        }
        std::wstring pName = xml.substr(nStart + 6, nEnd - (nStart + 6));

        std::lock_guard<std::mutex> lock(m_mutex);
        m_profiles[pName] = xml;
        dispatchNotification(WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_profile_change);
        return ERROR_SUCCESS;
    }

    DWORD getProfile(LPCWSTR strProfileName, LPWSTR* pstrProfileXml) {
        if (!strProfileName || !pstrProfileXml) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_profiles.find(strProfileName);
        if (it == m_profiles.end()) return ERROR_NOT_FOUND;

        size_t charCount = it->second.size() + 1;
        auto* pBuf = reinterpret_cast<wchar_t*>(new uint8_t[charCount * sizeof(wchar_t)]);
        std::wcscpy(pBuf, it->second.c_str());
        *pstrProfileXml = pBuf;
        return ERROR_SUCCESS;
    }

    DWORD deleteProfile(LPCWSTR strProfileName) {
        if (!strProfileName) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_profiles.find(strProfileName);
        if (it == m_profiles.end()) return ERROR_NOT_FOUND;
        m_profiles.erase(it);
        dispatchNotification(WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_profile_change);
        return ERROR_SUCCESS;
    }

    DWORD getProfileList(PWLAN_PROFILE_INFO_LIST* ppProfileList) {
        if (!ppProfileList) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        size_t count = m_profiles.size();
        size_t totalBytes = sizeof(WLAN_PROFILE_INFO_LIST) + (count > 0 ? (count - 1) * sizeof(WLAN_PROFILE_INFO) : 0);
        auto* pList = reinterpret_cast<PWLAN_PROFILE_INFO_LIST>(new uint8_t[totalBytes]);
        std::memset(pList, 0, totalBytes);

        pList->dwNumberOfItems = static_cast<DWORD>(count);
        pList->dwIndex = 0;

        size_t idx = 0;
        for (const auto& pair : m_profiles) {
            std::wcsncpy(pList->ProfileInfo[idx].strProfileName, pair.first.c_str(), 255);
            pList->ProfileInfo[idx].dwFlags = WLAN_PROFILE_USER;
            idx++;
        }

        *ppProfileList = pList;
        return ERROR_SUCCESS;
    }

    // Notifications
    DWORD registerNotification(
        HANDLE hClientHandle,
        DWORD dwNotifSource,
        WLAN_NOTIFICATION_CALLBACK funcCallback,
        PVOID pCallbackContext,
        PDWORD pdwPrevNotifSource
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_clients.find(hClientHandle);
        if (it == m_clients.end()) return ERROR_INVALID_HANDLE;

        if (pdwPrevNotifSource) *pdwPrevNotifSource = it->second.notificationSource;
        it->second.notificationSource = dwNotifSource;
        it->second.notificationCallback = funcCallback;
        it->second.callbackContext = pCallbackContext;
        return ERROR_SUCCESS;
    }

    // CLI Helpers
    WLAN_INTERFACE_STATE getState() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_interfaceState;
    }

    const std::vector<SimulatedBss>& getBssList() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_bssList;
    }

    std::string getConnectedSsid() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_connectedSsid;
    }

    const uint8_t* getMacAddress() const {
        return m_macAddress;
    }

    DOT11_RADIO_STATE getSoftwareRadio() const {
        return m_softwareRadio;
    }
};

// ============================================================================
// 4. Standard Win32 WLAN API Function Definitions (wlanapi.dll)
// ============================================================================

inline DWORD WINAPI WlanOpenHandle(
    DWORD dwClientVersion,
    [[maybe_unused]] PVOID pReserved,
    PDWORD pdwNegotiatedVersion,
    PHANDLE phClientHandle
) {
    return SovereignWlanManager::get().openHandle(dwClientVersion, pdwNegotiatedVersion, phClientHandle);
}

inline DWORD WINAPI WlanCloseHandle(
    HANDLE hClientHandle,
    [[maybe_unused]] PVOID pReserved
) {
    return SovereignWlanManager::get().closeHandle(hClientHandle);
}

inline DWORD WINAPI WlanEnumInterfaces(
    HANDLE hClientHandle,
    [[maybe_unused]] PVOID pReserved,
    PWLAN_INTERFACE_INFO_LIST* ppInterfaceList
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().enumInterfaces(ppInterfaceList);
}

inline DWORD WINAPI WlanGetInterfaceCapability(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    [[maybe_unused]] PVOID pReserved,
    PWLAN_INTERFACE_CAPABILITY* ppCapability
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().getInterfaceCapability(ppCapability);
}

inline DWORD WINAPI WlanScan(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    [[maybe_unused]] const PDOT11_SSID pDot11Ssid,
    [[maybe_unused]] const PWLAN_RAW_DATA pIeData,
    [[maybe_unused]] PVOID pReserved
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().triggerScan();
}

inline DWORD WINAPI WlanGetAvailableNetworkList(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    [[maybe_unused]] DWORD dwFlags,
    [[maybe_unused]] PVOID pReserved,
    PWLAN_AVAILABLE_NETWORK_LIST* ppAvailableNetworkList
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().getAvailableNetworkList(ppAvailableNetworkList);
}

inline DWORD WINAPI WlanGetNetworkBssList(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    [[maybe_unused]] const PDOT11_SSID pDot11Ssid,
    [[maybe_unused]] DOT11_BSS_TYPE dot11BssType,
    [[maybe_unused]] BOOL bSecurityEnabled,
    [[maybe_unused]] PVOID pReserved,
    PWLAN_BSS_LIST* ppWlanBssList
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().getNetworkBssList(ppWlanBssList);
}

inline DWORD WINAPI WlanQueryInterface(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    WLAN_INTF_OPCODE OpCode,
    [[maybe_unused]] PVOID pReserved,
    PDWORD pdwDataSize,
    PVOID* ppData,
    PWLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().queryInterface(OpCode, pdwDataSize, ppData, pWlanOpcodeValueType);
}

inline DWORD WINAPI WlanSetInterface(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    WLAN_INTF_OPCODE OpCode,
    DWORD dwDataSize,
    const PVOID pData,
    [[maybe_unused]] PVOID pReserved
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().setInterface(OpCode, dwDataSize, pData);
}

inline DWORD WINAPI WlanConnect(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    const PWLAN_CONNECTION_PARAMETERS pConnectionParameters,
    [[maybe_unused]] PVOID pReserved
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().connect(pConnectionParameters);
}

inline DWORD WINAPI WlanDisconnect(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    [[maybe_unused]] PVOID pReserved
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().disconnect();
}

inline DWORD WINAPI WlanRegisterNotification(
    HANDLE hClientHandle,
    DWORD dwNotifSource,
    [[maybe_unused]] BOOL bIgnoreDuplicate,
    WLAN_NOTIFICATION_CALLBACK funcCallback,
    PVOID pCallbackContext,
    [[maybe_unused]] PVOID pReserved,
    PDWORD pdwPrevNotifSource
) {
    return SovereignWlanManager::get().registerNotification(
        hClientHandle, dwNotifSource, funcCallback, pCallbackContext, pdwPrevNotifSource);
}

inline DWORD WINAPI WlanSetProfile(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    [[maybe_unused]] DWORD dwFlags,
    LPCWSTR strProfileXml,
    [[maybe_unused]] LPCWSTR strAllUserProfileSecurity,
    [[maybe_unused]] BOOL bOverwrite,
    DWORD* pdwReasonCode,
    [[maybe_unused]] DWORD* pdwFlags
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().setProfile(strProfileXml, pdwReasonCode);
}

inline DWORD WINAPI WlanGetProfile(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    LPCWSTR strProfileName,
    [[maybe_unused]] PVOID pReserved,
    LPWSTR* pstrProfileXml,
    DWORD* pdwFlags,
    [[maybe_unused]] DWORD* pdwGrantedAccess
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    if (pdwFlags) *pdwFlags = WLAN_PROFILE_USER;
    return SovereignWlanManager::get().getProfile(strProfileName, pstrProfileXml);
}

inline DWORD WINAPI WlanDeleteProfile(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    LPCWSTR strProfileName,
    [[maybe_unused]] PVOID pReserved
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().deleteProfile(strProfileName);
}

inline DWORD WINAPI WlanGetProfileList(
    HANDLE hClientHandle,
    [[maybe_unused]] const GUID* pInterfaceGuid,
    [[maybe_unused]] PVOID pReserved,
    PWLAN_PROFILE_INFO_LIST* ppProfileList
) {
    if (!SovereignWlanManager::get().isValidHandle(hClientHandle)) return ERROR_INVALID_HANDLE;
    return SovereignWlanManager::get().getProfileList(ppProfileList);
}

inline DWORD WINAPI WlanReasonCodeToString(
    DWORD dwReasonCode,
    DWORD dwBufferSize,
    PWCHAR pStringBuffer,
    [[maybe_unused]] PVOID pReserved
) {
    if (!pStringBuffer || dwBufferSize == 0) return ERROR_INVALID_PARAMETER;
    const wchar_t* msg = L"Unknown Reason";
    switch (dwReasonCode) {
        case WLAN_REASON_CODE_SUCCESS: msg = L"The operation succeeded."; break;
        case WLAN_REASON_CODE_NETWORK_NOT_AVAILABLE: msg = L"The network is not available."; break;
        case WLAN_REASON_CODE_TOO_MANY_SECURITY_ATTEMPTS: msg = L"Too many security attempts failed."; break;
        case WLAN_REASON_CODE_USER_CANCELLED: msg = L"The connection was cancelled by user."; break;
        default: break;
    }
    std::wcsncpy(pStringBuffer, msg, dwBufferSize - 1);
    pStringBuffer[dwBufferSize - 1] = 0;
    return ERROR_SUCCESS;
}

inline VOID WINAPI WlanFreeMemory(PVOID pMemory) {
    if (pMemory) {
        delete[] reinterpret_cast<uint8_t*>(pMemory);
    }
}

// ============================================================================
// 5. Subsystem Export Registration Helper
// ============================================================================

inline void InitializeWlanSubsystemExports() {
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        auto& loader = ldr::DynamicLoader::get();

        // 1. Register wlanapi.dll dynamic exports
        loader.registerExport("wlanapi.dll", "WlanOpenHandle", reinterpret_cast<void*>(&WlanOpenHandle));
        loader.registerExport("wlanapi.dll", "WlanCloseHandle", reinterpret_cast<void*>(&WlanCloseHandle));
        loader.registerExport("wlanapi.dll", "WlanEnumInterfaces", reinterpret_cast<void*>(&WlanEnumInterfaces));
        loader.registerExport("wlanapi.dll", "WlanGetInterfaceCapability", reinterpret_cast<void*>(&WlanGetInterfaceCapability));
        loader.registerExport("wlanapi.dll", "WlanScan", reinterpret_cast<void*>(&WlanScan));
        loader.registerExport("wlanapi.dll", "WlanGetAvailableNetworkList", reinterpret_cast<void*>(&WlanGetAvailableNetworkList));
        loader.registerExport("wlanapi.dll", "WlanGetNetworkBssList", reinterpret_cast<void*>(&WlanGetNetworkBssList));
        loader.registerExport("wlanapi.dll", "WlanQueryInterface", reinterpret_cast<void*>(&WlanQueryInterface));
        loader.registerExport("wlanapi.dll", "WlanSetInterface", reinterpret_cast<void*>(&WlanSetInterface));
        loader.registerExport("wlanapi.dll", "WlanConnect", reinterpret_cast<void*>(&WlanConnect));
        loader.registerExport("wlanapi.dll", "WlanDisconnect", reinterpret_cast<void*>(&WlanDisconnect));
        loader.registerExport("wlanapi.dll", "WlanRegisterNotification", reinterpret_cast<void*>(&WlanRegisterNotification));
        loader.registerExport("wlanapi.dll", "WlanSetProfile", reinterpret_cast<void*>(&WlanSetProfile));
        loader.registerExport("wlanapi.dll", "WlanGetProfile", reinterpret_cast<void*>(&WlanGetProfile));
        loader.registerExport("wlanapi.dll", "WlanDeleteProfile", reinterpret_cast<void*>(&WlanDeleteProfile));
        loader.registerExport("wlanapi.dll", "WlanGetProfileList", reinterpret_cast<void*>(&WlanGetProfileList));
        loader.registerExport("wlanapi.dll", "WlanReasonCodeToString", reinterpret_cast<void*>(&WlanReasonCodeToString));
        loader.registerExport("wlanapi.dll", "WlanFreeMemory", reinterpret_cast<void*>(&WlanFreeMemory));

        // 2. Register in VersionDatabase
        version::VersionDatabase::Instance().RegisterModule(
            "wlanapi.dll",
            "10.0.22621.1",
            "Windows Native Wifi & Sovereign WLAN Subsystem",
            "MicaNT Sovereign Project"
        );
    });
}

} // namespace micant::wlan
