#pragma once

#include <cstdint>
#include <string_view>
#include <vector>
#include <span>
#include <string>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "boot.hpp"

namespace micant::uefi {

// Standard UEFI Status Codes
inline constexpr uint64_t EFI_SUCCESS              = 0;
inline constexpr uint64_t EFI_LOAD_ERROR           = 0x8000000000000001ULL;
inline constexpr uint64_t EFI_INVALID_PARAMETER    = 0x8000000000000002ULL;
inline constexpr uint64_t EFI_UNSUPPORTED          = 0x8000000000000003ULL;
inline constexpr uint64_t EFI_BAD_BUFFER_SIZE      = 0x8000000000000004ULL;
inline constexpr uint64_t EFI_BUFFER_TOO_SMALL     = 0x8000000000000005ULL;
inline constexpr uint64_t EFI_NOT_READY            = 0x8000000000000006ULL;
inline constexpr uint64_t EFI_DEVICE_ERROR         = 0x8000000000000007ULL;
inline constexpr uint64_t EFI_NOT_FOUND            = 0x800000000000000EULL;

using EfiHandle = void*;
using EfiStatus = uint64_t;

/**
 * @brief 128-bit Globally Unique Identifier (EFI_GUID).
 */
struct EfiGuid {
    uint32_t data1{0};
    uint16_t data2{0};
    uint16_t data3{0};
    uint8_t  data4[8]{0};

    [[nodiscard]] constexpr bool operator==(const EfiGuid& other) const noexcept {
        if (data1 != other.data1 || data2 != other.data2 || data3 != other.data3) return false;
        for (size_t i = 0; i < 8; ++i) {
            if (data4[i] != other.data4[i]) return false;
        }
        return true;
    }
};

// Well-known standard UEFI Protocol & Configuration GUIDs
inline constexpr EfiGuid EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID = {
    0x9042a9de, 0x23dc, 0x4a38, { 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a }
};

inline constexpr EfiGuid ACPI_20_TABLE_GUID = {
    0x8868e871, 0xe4f1, 0x11d3, { 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 }
};

inline constexpr EfiGuid ACPI_10_TABLE_GUID = {
    0xeb9d2d30, 0x2d88, 0x11d3, { 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};

/**
 * @brief Standard UEFI Table Header.
 */
struct EfiTableHeader {
    uint64_t signature;
    uint32_t revision;
    uint32_t headerSize;
    uint32_t crc32;
    uint32_t reserved;
};

/**
 * @brief UEFI Graphics Pixel Formats.
 */
enum class EfiGraphicsPixelFormat : uint32_t {
    PixelRedGreenBlueReserved8BitPerColor  = 0,
    PixelBlueGreenRedReserved8BitPerColor  = 1,
    PixelBitMask                           = 2,
    PixelBltOnly                           = 3,
    PixelFormatMax                         = 4
};

/**
 * @brief Mode information returned by GOP.
 */
struct EfiGraphicsOutputModeInformation {
    uint32_t version{0};
    uint32_t horizontalResolution{0};
    uint32_t verticalResolution{0};
    EfiGraphicsPixelFormat pixelFormat{EfiGraphicsPixelFormat::PixelBlueGreenRedReserved8BitPerColor};
    struct {
        uint32_t redMask;
        uint32_t greenMask;
        uint32_t blueMask;
        uint32_t reservedMask;
    } pixelInformation{};
    uint32_t pixelsPerScanLine{0};
};

/**
 * @brief GOP Mode status structure.
 */
struct EfiGraphicsOutputProtocolMode {
    uint32_t maxMode{1};
    uint32_t mode{0};
    EfiGraphicsOutputModeInformation* info{nullptr};
    uint64_t sizeOfInfo{sizeof(EfiGraphicsOutputModeInformation)};
    uint64_t frameBufferBase{0};
    uint64_t frameBufferSize{0};
};

/**
 * @brief Graphics Output Protocol (GOP) Interface.
 */
struct EfiGraphicsOutputProtocol {
    void* queryMode{nullptr};
    void* setMode{nullptr};
    void* blt{nullptr};
    EfiGraphicsOutputProtocolMode* mode{nullptr};
};

/**
 * @brief UEFI Memory Types.
 */
enum class EfiMemoryType : uint32_t {
    EfiReservedMemoryType          = 0,
    EfiLoaderCode                  = 1,
    EfiLoaderData                  = 2,
    EfiBootServicesCode            = 3,
    EfiBootServicesData            = 4,
    EfiRuntimeServicesCode         = 5,
    EfiRuntimeServicesData         = 6,
    EfiConventionalMemory          = 7,
    EfiUnusableMemory              = 8,
    EfiACPIReclaimMemory           = 9,
    EfiACPIMemoryNVS               = 10,
    EfiMemoryMappedIO              = 11,
    EfiMemoryMappedIOPortSpace     = 12,
    EfiPalCode                     = 13,
    EfiPersistentMemory            = 14,
    EfiMaxMemoryType               = 15
};

/**
 * @brief UEFI Memory Descriptor.
 */
struct EfiMemoryDescriptor {
    uint32_t type{0};
    uint32_t pad{0};
    uint64_t physicalStart{0};
    uint64_t virtualStart{0};
    uint64_t numberOfPages{0};
    uint64_t attribute{0};
};

/**
 * @brief System Configuration Table entry (for ACPI RSDP, SMBIOS).
 */
struct EfiConfigurationTable {
    EfiGuid vendorGuid{};
    void*   vendorTable{nullptr};
};

/**
 * @brief UEFI Simple Text Output Protocol (for early firmware console).
 */
struct EfiSimpleTextOutputProtocol {
    void* reset{nullptr};
    EfiStatus (*outputString)(EfiSimpleTextOutputProtocol* self, const wchar_t* string){nullptr};
    void* testString{nullptr};
    void* queryMode{nullptr};
    void* setMode{nullptr};
    void* setAttribute{nullptr};
    EfiStatus (*clearScreen)(EfiSimpleTextOutputProtocol* self){nullptr};
    void* setCursorPosition{nullptr};
    void* enableCursor{nullptr};
    void* mode{nullptr};
};

/**
 * @brief UEFI Boot Services Table.
 */
struct EfiBootServices {
    EfiTableHeader hdr;

    // Task Priority Services
    void* raiseTPL;
    void* restoreTPL;

    // Memory Services
    void* allocatePages;
    void* freePages;
    EfiStatus (*getMemoryMap)(
        uint64_t* memoryMapSize,
        EfiMemoryDescriptor* memoryMap,
        uint64_t* mapKey,
        uint64_t* descriptorSize,
        uint32_t* descriptorVersion
    );
    void* allocatePool;
    void* freePool;

    // Event & Timer Services
    void* createEvent;
    void* setTimer;
    void* waitForEvent;
    void* signalEvent;
    void* closeEvent;
    void* checkEvent;

    // Protocol Handler Services
    void* installProtocolInterface;
    void* reinstallProtocolInterface;
    void* uninstallProtocolInterface;
    void* handleProtocol;
    void* reserved;
    void* registerProtocolNotify;
    void* locateHandle;
    void* locateDevicePath;
    void* installConfigurationTable;

    // Image Services
    void* loadImage;
    void* startImage;
    void* exit;
    void* unloadImage;
    EfiStatus (*exitBootServices)(EfiHandle imageHandle, uint64_t mapKey);

    // Miscellaneous Services
    void* getNextMonotonicCount;
    void* stall;
    void* setWatchdogTimer;

    // Driver Support Services
    void* connectController;
    void* disconnectController;

    // Open/Close Protocol Services
    void* openProtocol;
    void* closeProtocol;
    void* openProtocolInformation;

    // Library Services
    void* protocolsPerHandle;
    void* locateHandleBuffer;
    EfiStatus (*locateProtocol)(const EfiGuid* protocol, void* registration, void** interface);
};

/**
 * @brief UEFI System Table (primary pointer passed into EFI application entry point).
 */
struct EfiSystemTable {
    EfiTableHeader hdr;
    wchar_t* firmwareVendor;
    uint32_t firmwareRevision;
    EfiHandle consoleInHandle;
    void* conIn;
    EfiHandle consoleOutHandle;
    EfiSimpleTextOutputProtocol* conOut;
    EfiHandle standardErrorHandle;
    EfiSimpleTextOutputProtocol* stdErr;
    void* runtimeServices;
    EfiBootServices* bootServices;
    uint64_t numberOfTableEntries;
    EfiConfigurationTable* configurationTable;
};

// ============================================================================
// Firmware Translation: UEFI -> MicaNT LOADER_PARAMETER_BLOCK
// ============================================================================

inline boot::LoaderMemoryType EfiMemoryTypeToNt(EfiMemoryType type) noexcept {
    switch (type) {
        case EfiMemoryType::EfiConventionalMemory:
            return boot::LoaderMemoryType::LoaderFree;
        case EfiMemoryType::EfiLoaderCode:
            return boot::LoaderMemoryType::LoaderSystemCode;
        case EfiMemoryType::EfiLoaderData:
            return boot::LoaderMemoryType::LoaderOsloaderHeap;
        case EfiMemoryType::EfiBootServicesCode:
        case EfiMemoryType::EfiBootServicesData:
            return boot::LoaderMemoryType::LoaderFirmwareTemporary;
        case EfiMemoryType::EfiRuntimeServicesCode:
        case EfiMemoryType::EfiRuntimeServicesData:
            return boot::LoaderMemoryType::LoaderFirmwarePermanent;
        case EfiMemoryType::EfiACPIReclaimMemory:
        case EfiMemoryType::EfiACPIMemoryNVS:
        case EfiMemoryType::EfiMemoryMappedIO:
            return boot::LoaderMemoryType::LoaderSpecialMemory;
        case EfiMemoryType::EfiUnusableMemory:
            return boot::LoaderMemoryType::LoaderBad;
        default:
            return boot::LoaderMemoryType::LoaderReserve;
    }
}

/**
 * @brief Clean-room translation of UEFI firmware parameters into NT LOADER_PARAMETER_BLOCK.
 */
inline boot::LoaderParameterBlock BuildLpbFromUefi(
    const EfiSystemTable* systemTable,
    const EfiGraphicsOutputProtocol* gop,
    std::span<const EfiMemoryDescriptor> memoryMap,
    std::string_view loadOptions = "/DEBUG /DEBUGPORT=COM1 /BAUDRATE=115200 /NOEXECUTE=ALWAYS /ZERO_TELEMETRY=1"
) {
    boot::LoaderParameterBlock lpb;
    lpb.arcBootDeviceName = L"multi(0)disk(0)rdisk(0)partition(1)";
    lpb.arcHalDeviceName  = L"multi(0)disk(0)rdisk(0)partition(1)";
    lpb.ntBootPathName    = L"\\Windows\\";
    lpb.ntHalPathName     = L"\\Windows\\System32\\";
    lpb.loadOptions       = std::string(loadOptions);

    // 1. Ingest GOP linear framebuffer
    if (gop && gop->mode && gop->mode->info) {
        lpb.framebuffer.physicalBase     = gop->mode->frameBufferBase;
        lpb.framebuffer.size             = gop->mode->frameBufferSize;
        lpb.framebuffer.width            = gop->mode->info->horizontalResolution;
        lpb.framebuffer.height           = gop->mode->info->verticalResolution;
        lpb.framebuffer.pixelsPerScanLine= gop->mode->info->pixelsPerScanLine;
        lpb.framebuffer.pixelFormat      = static_cast<uint32_t>(gop->mode->info->pixelFormat);
    }

    // 2. Discover ACPI 2.0 / 1.0 Root System Description Pointer (RSDP)
    if (systemTable && systemTable->configurationTable) {
        for (uint64_t i = 0; i < systemTable->numberOfTableEntries; ++i) {
            const auto& entry = systemTable->configurationTable[i];
            if (entry.vendorGuid == ACPI_20_TABLE_GUID || entry.vendorGuid == ACPI_10_TABLE_GUID) {
                lpb.acpiTablePhysicalAddress = reinterpret_cast<uint64_t>(entry.vendorTable);
                break;
            }
        }
    }

    // 3. Translate UEFI Memory Map to NT Memory Allocation Descriptors
    for (const auto& desc : memoryMap) {
        lpb.memoryDescriptors.push_back({
            .memoryType = EfiMemoryTypeToNt(static_cast<EfiMemoryType>(desc.type)),
            .basePage   = desc.physicalStart / 4096,
            .pageCount  = desc.numberOfPages
        });
    }

    // 4. Default Core Kernel Boot Modules
    lpb.bootModules.push_back({
        .baseDllName = L"ntoskrnl.exe",
        .fullDllName = L"\\Windows\\System32\\ntoskrnl.exe",
        .dllBase = 0xFFFFF80000000000ULL,
        .sizeOfImage = 12 * 1024 * 1024,
        .entryPoint = 0xFFFFF80000100000ULL
    });

    lpb.bootModules.push_back({
        .baseDllName = L"hal.dll",
        .fullDllName = L"\\Windows\\System32\\hal.dll",
        .dllBase = 0xFFFFF80001000000ULL,
        .sizeOfImage = 2 * 1024 * 1024,
        .entryPoint = 0xFFFFF80001010000ULL
    });

    lpb.bootModules.push_back({
        .baseDllName = L"fastfat.sys",
        .fullDllName = L"\\Windows\\System32\\drivers\\fastfat.sys",
        .dllBase = 0xFFFFF80001200000ULL,
        .sizeOfImage = 1 * 1024 * 1024,
        .entryPoint = 0xFFFFF80001208000ULL
    });

    return lpb;
}

} // namespace micant::uefi
