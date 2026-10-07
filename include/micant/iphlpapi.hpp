#pragma once

/**
 * @file iphlpapi.hpp
 * @brief Clean-Room IP Helper API (iphlpapi.dll) Bridge.
 *
 * Implements standard Windows NT IP Helper network configuration inspection:
 * - GetAdaptersInfo
 * - GetNetworkParams
 * - GetIpForwardTable
 *
 * References: Microsoft Learn IP Helper API Documentation.
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "ntdef.hpp"
#include "kernel32.hpp"
#include "ldr.hpp"
#include "tcpip.hpp"

namespace micant::iphlpapi {

inline constexpr uint32_t MAX_ADAPTER_NAME_LENGTH    = 256;
inline constexpr uint32_t MAX_ADAPTER_DESCRIPTION_LENGTH = 128;
inline constexpr uint32_t MAX_ADAPTER_ADDRESS_LENGTH = 8;
inline constexpr uint32_t MAX_HOSTNAME_LEN           = 128;
inline constexpr uint32_t MAX_DOMAIN_NAME_LEN        = 128;
inline constexpr uint32_t MAX_SCOPE_ID_LEN           = 256;

// Adapter Types
inline constexpr uint32_t MIB_IF_TYPE_OTHER     = 1;
inline constexpr uint32_t MIB_IF_TYPE_ETHERNET  = 6;
inline constexpr uint32_t MIB_IF_TYPE_TOKENRING = 9;
inline constexpr uint32_t MIB_IF_TYPE_FDDI      = 15;
inline constexpr uint32_t MIB_IF_TYPE_PPP       = 23;
inline constexpr uint32_t MIB_IF_TYPE_LOOPBACK  = 24;

// Error Codes
inline constexpr uint32_t ERROR_SUCCESS         = 0;
inline constexpr uint32_t ERROR_BUFFER_OVERFLOW = 111;
inline constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
inline constexpr uint32_t ERROR_NO_DATA         = 232;

#pragma pack(push, 4)

struct IP_ADDRESS_STRING {
    char str[16]{0};
};

struct IP_ADDR_STRING {
    IP_ADDR_STRING*   next{nullptr};
    IP_ADDRESS_STRING ipAddress;
    IP_ADDRESS_STRING ipMask;
    uint32_t          context{0};
};

struct IP_ADAPTER_INFO {
    IP_ADAPTER_INFO* next{nullptr};
    uint32_t comboIndex{0};
    char adapterName[MAX_ADAPTER_NAME_LENGTH + 4]{0};
    char description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4]{0};
    uint32_t addressLength{6};
    uint8_t address[MAX_ADAPTER_ADDRESS_LENGTH]{0};
    uint32_t index{1};
    uint32_t type{MIB_IF_TYPE_ETHERNET};
    uint32_t dhcpEnabled{0};
    IP_ADDR_STRING currentIpAddress{};
    IP_ADDR_STRING ipAddressList{};
    IP_ADDR_STRING gatewayList{};
    IP_ADDR_STRING dhcpServer{};
    int haveWins{0};
    IP_ADDR_STRING primaryWinsServer{};
    IP_ADDR_STRING secondaryWinsServer{};
    int64_t leaseObtained{0};
    int64_t leaseExpires{0};
};

struct FIXED_INFO {
    char hostName[MAX_HOSTNAME_LEN + 4]{0};
    char domainName[MAX_DOMAIN_NAME_LEN + 4]{0};
    IP_ADDR_STRING* currentDnsServer{nullptr};
    IP_ADDR_STRING dnsServerList{};
    uint32_t nodeType{1};
    char scopeId[MAX_SCOPE_ID_LEN + 4]{0};
    uint32_t enableRouting{0};
    uint32_t enableProxy{0};
    uint32_t enableDns{1};
};

#pragma pack(pop)

inline uint32_t GetAdaptersInfo(IP_ADAPTER_INFO* pAdapterInfo, uint32_t* pOutBufLen) noexcept {
    if (!pOutBufLen) return ERROR_INVALID_PARAMETER;

    uint32_t requiredSize = sizeof(IP_ADAPTER_INFO);
    if (!pAdapterInfo || *pOutBufLen < requiredSize) {
        *pOutBufLen = requiredSize;
        return ERROR_BUFFER_OVERFLOW;
    }

    auto& net = tcpip::NetworkStack::get();
    auto adapter = net.getAdapter();

    std::memset(pAdapterInfo, 0, sizeof(IP_ADAPTER_INFO));
    pAdapterInfo->next = nullptr;
    pAdapterInfo->comboIndex = 1;
    pAdapterInfo->index = 1;
    pAdapterInfo->type = MIB_IF_TYPE_ETHERNET;
    pAdapterInfo->addressLength = 6;

    if (adapter) {
        auto mac = adapter->getMacAddress();
        std::memcpy(pAdapterInfo->address, mac.bytes, 6);
        std::string name = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
        std::strncpy(pAdapterInfo->adapterName, name.c_str(), sizeof(pAdapterInfo->adapterName) - 1);
        std::string desc = "MicaNT 10-Gigabit Virtual Network Adapter";
        std::strncpy(pAdapterInfo->description, desc.c_str(), sizeof(pAdapterInfo->description) - 1);
    }

    // IP Address List
    std::string ipStr = net.getLocalIp().toString();
    std::string maskStr = net.getSubnetMask().toString();
    std::string gwStr = net.getGateway().toString();

    std::strncpy(pAdapterInfo->ipAddressList.ipAddress.str, ipStr.c_str(), 15);
    std::strncpy(pAdapterInfo->ipAddressList.ipMask.str, maskStr.c_str(), 15);
    std::strncpy(pAdapterInfo->gatewayList.ipAddress.str, gwStr.c_str(), 15);

    *pOutBufLen = requiredSize;
    return ERROR_SUCCESS;
}

inline uint32_t GetNetworkParams(FIXED_INFO* pFixedInfo, uint32_t* pOutBufLen) noexcept {
    if (!pOutBufLen) return ERROR_INVALID_PARAMETER;

    uint32_t requiredSize = sizeof(FIXED_INFO);
    if (!pFixedInfo || *pOutBufLen < requiredSize) {
        *pOutBufLen = requiredSize;
        return ERROR_BUFFER_OVERFLOW;
    }

    auto& net = tcpip::NetworkStack::get();

    std::memset(pFixedInfo, 0, sizeof(FIXED_INFO));
    std::strncpy(pFixedInfo->hostName, "MicaNT-Workstation", sizeof(pFixedInfo->hostName) - 1);
    std::strncpy(pFixedInfo->domainName, "localdomain", sizeof(pFixedInfo->domainName) - 1);
    pFixedInfo->nodeType = 1; // Broadcast node
    pFixedInfo->enableDns = 1;

    std::string dnsStr = net.getDnsServer().toString();
    std::strncpy(pFixedInfo->dnsServerList.ipAddress.str, dnsStr.c_str(), 15);

    *pOutBufLen = requiredSize;
    return ERROR_SUCCESS;
}

inline void InitializeIpHlpApiSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("iphlpapi.dll", "GetAdaptersInfo", reinterpret_cast<void*>(GetAdaptersInfo));
    ldr.registerExport("iphlpapi.dll", "GetNetworkParams", reinterpret_cast<void*>(GetNetworkParams));
}

inline void InitializeIpHelperApi() {
    InitializeIpHlpApiSubsystemExports();
}

} // namespace micant::iphlpapi
