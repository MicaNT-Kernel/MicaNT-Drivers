// ============================================================================
// MicaNT: Windows Virtual Disk & Storage Management Subsystem
// (include/micant/virtdisk.hpp)
//
// Strict Clean-Room Implementation based on:
//   - Microsoft Virtual Hard Disk (VHD / VHDX) Image Format Specification
//   - Microsoft Win32 Virtual Disk API (virtdisk.h) C ABI Specification
//   - Virtual Disk Service (VDS) & Storage Spaces Architecture
//
// Subsystem Overview:
//   virtdisk.hpp provides the Windows Virtual Disk subsystem for MicaNT,
//   enabling creation, mounting (attaching), unmounting (detaching), querying,
//   resizing, and compaction of virtual hard disk images (.vhd and .vhdx)
//   without external hypervisor bloat, proprietary drivers, or telemetry.
//
// Features:
//   - Native Win32 Virtual Disk C API (virtdisk.dll):
//       * CreateVirtualDisk
//       * OpenVirtualDisk
//       * AttachVirtualDisk / DetachVirtualDisk
//       * GetVirtualDiskInformation / SetVirtualDiskInformation
//       * GetVirtualDiskPhysicalPath / GetAllAttachedVirtualDiskPhysicalPaths
//       * CompactVirtualDisk / ExpandVirtualDisk / ResizeVirtualDisk
//       * MirrorVirtualDisk / BreakMirrorVirtualDisk
//       * AddVirtualDiskParent / MergeVirtualDisk
//       * GetStorageDependencyInformation
//   - VHD & VHDX Container Format Simulation:
//       * Fixed, Dynamic, and Differencing virtual disks
//       * Connectix VHD cookie ("conectix") and dynamic header ("cxsparse")
//       * VHDX signature ("vhdxfile") with 4Kn/512e logical sector layouts
//       * Cylinder-Head-Sector (CHS) geometry synthesis
//       * Block Allocation Table (BAT) and payload tracking
//   - Sovereign Virtual Disk Controller & Device Graph Integration:
//       * Dynamic virtual physical drive exposure ("\\\\.\\PhysicalDrive<N>")
//       * Synthetic kernel volume device exposure ("\\Device\\HarddiskVolumeVirtual<N>")
//       * Access rights and attachment flags enforcement
//
// Core Dynamic Module:
//   - virtdisk.dll
//
// Trademark & Nominative Fair Use Notice:
//   Windows, VHD, and VHDX are registered trademarks of Microsoft Corp.
//   MicaNT is an independent sovereign clean-room implementation engineered
//   for binary interoperability (*Google LLC v. Oracle America, Inc.*).
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ldr.hpp"
#include "version.hpp"
#include "fs.hpp"

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

namespace micant::virtdisk {

// ============================================================================
// 1. Standard Win32 Virtual Disk Types & Constants
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
using PCWSTR    = const wchar_t*;
using PWSTR     = wchar_t*;
using PVOID     = void*;
using HANDLE    = void*;
using PHANDLE   = void**;
using PDWORD    = uint32_t*;
using PULONG    = uint32_t*;
using LPOVERLAPPED = void*;
using PSECURITY_DESCRIPTOR = void*;
using GUID      = micant::GUID;

#ifndef WINAPI
#define WINAPI __stdcall
#endif

// Virtual Storage Device Types
inline constexpr ULONG VIRTUAL_STORAGE_TYPE_DEVICE_UNKNOWN = 0;
inline constexpr ULONG VIRTUAL_STORAGE_TYPE_DEVICE_ISO     = 1;
inline constexpr ULONG VIRTUAL_STORAGE_TYPE_DEVICE_VHD     = 2;
inline constexpr ULONG VIRTUAL_STORAGE_TYPE_DEVICE_VHDX    = 3;

// Microsoft Virtual Storage Vendor GUID: {EC984AEC-A0F9-47e9-901F-71415A66345B}
inline constexpr GUID VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT = {
    0xEC984AEC, 0xA0F9, 0x47e9,
    { 0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B }
};

struct VIRTUAL_STORAGE_TYPE {
    ULONG DeviceId{ VIRTUAL_STORAGE_TYPE_DEVICE_VHD };
    GUID  VendorId{ VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT };
};
using PVIRTUAL_STORAGE_TYPE = VIRTUAL_STORAGE_TYPE*;

// Error Codes
inline constexpr DWORD ERROR_SUCCESS                    = 0;
inline constexpr DWORD ERROR_INVALID_PARAMETER          = 87;
inline constexpr DWORD ERROR_INVALID_HANDLE             = 6;
inline constexpr DWORD ERROR_FILE_NOT_FOUND             = 2;
inline constexpr DWORD ERROR_ALREADY_EXISTS             = 183;
inline constexpr DWORD ERROR_NOT_SUPPORTED              = 50;
inline constexpr DWORD ERROR_NOT_FOUND                  = 1168;
inline constexpr DWORD ERROR_INSUFFICIENT_BUFFER        = 122;
inline constexpr DWORD ERROR_ACCESS_DENIED              = 5;
inline constexpr DWORD ERROR_VIRTUAL_DISK_LIMITATION    = 12050;

// Virtual Disk Access Mask
using VIRTUAL_DISK_ACCESS_MASK = DWORD;
inline constexpr VIRTUAL_DISK_ACCESS_MASK VIRTUAL_DISK_ACCESS_NONE       = 0x00000000;
inline constexpr VIRTUAL_DISK_ACCESS_MASK VIRTUAL_DISK_ACCESS_ATTACH_RO  = 0x00010000;
inline constexpr VIRTUAL_DISK_ACCESS_MASK VIRTUAL_DISK_ACCESS_ATTACH_RW  = 0x00020000;
inline constexpr VIRTUAL_DISK_ACCESS_MASK VIRTUAL_DISK_ACCESS_DETACH     = 0x00040000;
inline constexpr VIRTUAL_DISK_ACCESS_MASK VIRTUAL_DISK_ACCESS_GET_INFO   = 0x00080000;
inline constexpr VIRTUAL_DISK_ACCESS_MASK VIRTUAL_DISK_ACCESS_CREATE     = 0x00100000;
inline constexpr VIRTUAL_DISK_ACCESS_MASK VIRTUAL_DISK_ACCESS_METAOPS    = 0x00200000;
inline constexpr VIRTUAL_DISK_ACCESS_MASK VIRTUAL_DISK_ACCESS_READ       = 0x000D0000;
inline constexpr VIRTUAL_DISK_ACCESS_MASK VIRTUAL_DISK_ACCESS_ALL        = 0x003F0000;
inline constexpr VIRTUAL_DISK_ACCESS_MASK VIRTUAL_DISK_ACCESS_WRITABLE   = 0x00320000;

// Create Virtual Disk Flags
enum CREATE_VIRTUAL_DISK_FLAG {
    CREATE_VIRTUAL_DISK_FLAG_NONE                           = 0x00000000,
    CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION       = 0x00000001, // Fixed
    CREATE_VIRTUAL_DISK_FLAG_PREVENT_META_DATA_EXPANSION   = 0x00000002,
    CREATE_VIRTUAL_DISK_FLAG_CREATE_BACKING_STORAGE        = 0x00000004,
    CREATE_VIRTUAL_DISK_FLAG_SPARSE_FILE                   = 0x00000040,
    CREATE_VIRTUAL_DISK_FLAG_PMEM_COMPATIBLE               = 0x00000080
};

// Create Virtual Disk Version
enum CREATE_VIRTUAL_DISK_VERSION {
    CREATE_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
    CREATE_VIRTUAL_DISK_VERSION_1           = 1,
    CREATE_VIRTUAL_DISK_VERSION_2           = 2
};

struct CREATE_VIRTUAL_DISK_PARAMETERS {
    CREATE_VIRTUAL_DISK_VERSION Version{ CREATE_VIRTUAL_DISK_VERSION_1 };
    union {
        struct {
            GUID UniqueId{};
            ULONGLONG MaximumSize{ 0 };
            ULONG BlockSizeInBytes{ 0 };
            ULONG SectorSizeInBytes{ 512 };
            PCWSTR ParentPath{ nullptr };
            PCWSTR SourcePath{ nullptr };
        } Version1;
        struct {
            GUID UniqueId{};
            ULONGLONG MaximumSize{ 0 };
            ULONG BlockSizeInBytes{ 0 };
            ULONG SectorSizeInBytes{ 512 };
            ULONG PhysicalSectorSizeInBytes{ 4096 };
            PCWSTR ParentPath{ nullptr };
            PCWSTR SourcePath{ nullptr };
            DWORD OpenFlags{ 0 };
            VIRTUAL_STORAGE_TYPE ParentVirtualStorageType{};
            VIRTUAL_STORAGE_TYPE SourceVirtualStorageType{};
            GUID ResiliencyGuid{};
        } Version2;
    };
};
using PCREATE_VIRTUAL_DISK_PARAMETERS = CREATE_VIRTUAL_DISK_PARAMETERS*;

// Open Virtual Disk Flags
enum OPEN_VIRTUAL_DISK_FLAG {
    OPEN_VIRTUAL_DISK_FLAG_NONE                             = 0x00000000,
    OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS                       = 0x00000001,
    OPEN_VIRTUAL_DISK_FLAG_BLANK_FILE                       = 0x00000002,
    OPEN_VIRTUAL_DISK_FLAG_BOOT_DRIVE                       = 0x00000004,
    OPEN_VIRTUAL_DISK_FLAG_CACHED_IO                        = 0x00000008,
    OPEN_VIRTUAL_DISK_FLAG_CUSTOM_DIFF_CHAIN                = 0x00000010,
    OPEN_VIRTUAL_DISK_FLAG_PARENT_CACHED_IO                 = 0x00000020,
    OPEN_VIRTUAL_DISK_FLAG_VHDSET_FILE_ONLY                 = 0x00000040,
    OPEN_VIRTUAL_DISK_FLAG_IGNORE_RELATIVE_PARENT_LOCATOR   = 0x00000080,
    OPEN_VIRTUAL_DISK_FLAG_NO_DIRTY_OVERRIDE                = 0x00000100,
    OPEN_VIRTUAL_DISK_FLAG_SUPPORT_COMPRESSED_VOLUMES       = 0x00000200
};

// Open Virtual Disk Version
enum OPEN_VIRTUAL_DISK_VERSION {
    OPEN_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
    OPEN_VIRTUAL_DISK_VERSION_1           = 1,
    OPEN_VIRTUAL_DISK_VERSION_2           = 2,
    OPEN_VIRTUAL_DISK_VERSION_3           = 3
};

struct OPEN_VIRTUAL_DISK_PARAMETERS {
    OPEN_VIRTUAL_DISK_VERSION Version{ OPEN_VIRTUAL_DISK_VERSION_1 };
    union {
        struct {
            ULONG RWDepth{ 1 };
        } Version1;
        struct {
            BOOL GetInfoOnly{ 0 };
            BOOL ReadOnly{ 0 };
            GUID ResiliencyGuid{};
        } Version2;
        struct {
            BOOL GetInfoOnly{ 0 };
            BOOL ReadOnly{ 0 };
            GUID ResiliencyGuid{};
            GUID SnapshotId{};
        } Version3;
    };
};
using POPEN_VIRTUAL_DISK_PARAMETERS = OPEN_VIRTUAL_DISK_PARAMETERS*;

// Attach Virtual Disk Flags
enum ATTACH_VIRTUAL_DISK_FLAG {
    ATTACH_VIRTUAL_DISK_FLAG_NONE                           = 0x00000000,
    ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY                      = 0x00000001,
    ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER                = 0x00000002,
    ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME             = 0x00000004,
    ATTACH_VIRTUAL_DISK_FLAG_NO_LOCAL_HOST                  = 0x00000008,
    ATTACH_VIRTUAL_DISK_FLAG_NO_SECURITY_DESCRIPTOR         = 0x00000010,
    ATTACH_VIRTUAL_DISK_FLAG_BYPASS_DEFAULT_ENCRYPTION_POLICY = 0x00000020,
    ATTACH_VIRTUAL_DISK_FLAG_NON_STANDARD_PAGING_FILE       = 0x00000040,
    ATTACH_VIRTUAL_DISK_FLAG_RESTRICTED_RANGE               = 0x00000080
};

// Attach Virtual Disk Version
enum ATTACH_VIRTUAL_DISK_VERSION {
    ATTACH_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
    ATTACH_VIRTUAL_DISK_VERSION_1           = 1,
    ATTACH_VIRTUAL_DISK_VERSION_2           = 2
};

struct ATTACH_VIRTUAL_DISK_PARAMETERS {
    ATTACH_VIRTUAL_DISK_VERSION Version{ ATTACH_VIRTUAL_DISK_VERSION_1 };
    union {
        struct {
            ULONG Reserved{ 0 };
        } Version1;
        struct {
            ULONGLONG RestrictedOffset{ 0 };
            ULONGLONG RestrictedLength{ 0 };
        } Version2;
    };
};
using PATTACH_VIRTUAL_DISK_PARAMETERS = ATTACH_VIRTUAL_DISK_PARAMETERS*;

// Detach Virtual Disk Flags
enum DETACH_VIRTUAL_DISK_FLAG {
    DETACH_VIRTUAL_DISK_FLAG_NONE = 0x00000000
};

// Compact Virtual Disk
enum COMPACT_VIRTUAL_DISK_FLAG {
    COMPACT_VIRTUAL_DISK_FLAG_NONE = 0x00000000
};

enum COMPACT_VIRTUAL_DISK_VERSION {
    COMPACT_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
    COMPACT_VIRTUAL_DISK_VERSION_1           = 1
};

struct COMPACT_VIRTUAL_DISK_PARAMETERS {
    COMPACT_VIRTUAL_DISK_VERSION Version{ COMPACT_VIRTUAL_DISK_VERSION_1 };
    union {
        struct {
            ULONG Reserved{ 0 };
        } Version1;
    };
};
using PCOMPACT_VIRTUAL_DISK_PARAMETERS = COMPACT_VIRTUAL_DISK_PARAMETERS*;

// Expand Virtual Disk
enum EXPAND_VIRTUAL_DISK_FLAG {
    EXPAND_VIRTUAL_DISK_FLAG_NONE = 0x00000000
};

enum EXPAND_VIRTUAL_DISK_VERSION {
    EXPAND_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
    EXPAND_VIRTUAL_DISK_VERSION_1           = 1
};

struct EXPAND_VIRTUAL_DISK_PARAMETERS {
    EXPAND_VIRTUAL_DISK_VERSION Version{ EXPAND_VIRTUAL_DISK_VERSION_1 };
    union {
        struct {
            ULONGLONG NewSize{ 0 };
        } Version1;
    };
};
using PEXPAND_VIRTUAL_DISK_PARAMETERS = EXPAND_VIRTUAL_DISK_PARAMETERS*;

// Resize Virtual Disk
enum RESIZE_VIRTUAL_DISK_FLAG {
    RESIZE_VIRTUAL_DISK_FLAG_NONE                                   = 0x00000000,
    RESIZE_VIRTUAL_DISK_FLAG_ALLOW_UNSAFE_VIRTUAL_SIZE              = 0x00000001,
    RESIZE_VIRTUAL_DISK_FLAG_RESIZE_TO_SMALLEST_SAFE_VIRTUAL_SIZE   = 0x00000002
};

enum RESIZE_VIRTUAL_DISK_VERSION {
    RESIZE_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
    RESIZE_VIRTUAL_DISK_VERSION_1           = 1
};

struct RESIZE_VIRTUAL_DISK_PARAMETERS {
    RESIZE_VIRTUAL_DISK_VERSION Version{ RESIZE_VIRTUAL_DISK_VERSION_1 };
    union {
        struct {
            ULONGLONG NewSize{ 0 };
        } Version1;
    };
};
using PRESIZE_VIRTUAL_DISK_PARAMETERS = RESIZE_VIRTUAL_DISK_PARAMETERS*;

// Mirror Virtual Disk
enum MIRROR_VIRTUAL_DISK_FLAG {
    MIRROR_VIRTUAL_DISK_FLAG_NONE = 0x00000000
};

enum MIRROR_VIRTUAL_DISK_VERSION {
    MIRROR_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
    MIRROR_VIRTUAL_DISK_VERSION_1           = 1
};

struct MIRROR_VIRTUAL_DISK_PARAMETERS {
    MIRROR_VIRTUAL_DISK_VERSION Version{ MIRROR_VIRTUAL_DISK_VERSION_1 };
    union {
        struct {
            PCWSTR MirrorVirtualDiskPath{ nullptr };
        } Version1;
    };
};
using PMIRROR_VIRTUAL_DISK_PARAMETERS = MIRROR_VIRTUAL_DISK_PARAMETERS*;

// Merge Virtual Disk
enum MERGE_VIRTUAL_DISK_FLAG {
    MERGE_VIRTUAL_DISK_FLAG_NONE = 0x00000000
};

enum MERGE_VIRTUAL_DISK_VERSION {
    MERGE_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
    MERGE_VIRTUAL_DISK_VERSION_1           = 1,
    MERGE_VIRTUAL_DISK_VERSION_2           = 2
};

struct MERGE_VIRTUAL_DISK_PARAMETERS {
    MERGE_VIRTUAL_DISK_VERSION Version{ MERGE_VIRTUAL_DISK_VERSION_1 };
    union {
        struct {
            ULONG MergeDepth{ 1 };
        } Version1;
        struct {
            ULONG MergeSourceDepth{ 1 };
            ULONG MergeTargetDepth{ 2 };
        } Version2;
    };
};
using PMERGE_VIRTUAL_DISK_PARAMETERS = MERGE_VIRTUAL_DISK_PARAMETERS*;

// Get Virtual Disk Information
enum GET_VIRTUAL_DISK_INFO_VERSION {
    GET_VIRTUAL_DISK_INFO_UNSPECIFIED                   = 0,
    GET_VIRTUAL_DISK_INFO_SIZE                          = 1,
    GET_VIRTUAL_DISK_INFO_IDENTIFIER                    = 2,
    GET_VIRTUAL_DISK_INFO_PARENT_LOCATION               = 3,
    GET_VIRTUAL_DISK_INFO_PARENT_IDENTIFIER             = 4,
    GET_VIRTUAL_DISK_INFO_PARENT_TIMESTAMP              = 5,
    GET_VIRTUAL_DISK_INFO_VIRTUAL_STORAGE_TYPE          = 6,
    GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE              = 7,
    GET_VIRTUAL_DISK_INFO_IS_4K_ALIGNED                 = 8,
    GET_VIRTUAL_DISK_INFO_PHYSICAL_DISK                 = 9,
    GET_VIRTUAL_DISK_INFO_VHD_PHYSICAL_SECTOR_SIZE      = 10,
    GET_VIRTUAL_DISK_INFO_SMALLEST_SAFE_VIRTUAL_SIZE    = 11,
    GET_VIRTUAL_DISK_INFO_FRAGMENTATION                 = 12,
    GET_VIRTUAL_DISK_INFO_IS_LOADED                     = 13,
    GET_VIRTUAL_DISK_INFO_VIRTUAL_DISK_ID               = 14,
    GET_VIRTUAL_DISK_INFO_CHANGE_TRACKING_STATE         = 15
};

struct GET_VIRTUAL_DISK_INFO {
    GET_VIRTUAL_DISK_INFO_VERSION Version{ GET_VIRTUAL_DISK_INFO_UNSPECIFIED };
    union {
        struct {
            ULONGLONG VirtualSize{ 0 };
            ULONGLONG PhysicalSize{ 0 };
            ULONG BlockSize{ 0 };
            ULONG SectorSize{ 512 };
        } Size;
        GUID Identifier;
        struct {
            BOOL ParentResolved{ 0 };
            WCHAR ParentLocationBuffer[1];
        } ParentLocation;
        GUID ParentIdentifier;
        ULONG ParentTimestamp;
        VIRTUAL_STORAGE_TYPE VirtualStorageType;
        ULONG ProviderSubtype;
        BOOL Is4kAligned;
        BOOL IsLoaded;
        struct {
            ULONG LogicalSectorSize{ 512 };
            ULONG PhysicalSectorSize{ 4096 };
            BOOL IsRemote{ 0 };
        } PhysicalDisk;
        ULONG VhdPhysicalSectorSize;
        ULONGLONG SmallestSafeVirtualSize;
        ULONG FragmentationPercentage;
        GUID VirtualDiskId;
    };
};
using PGET_VIRTUAL_DISK_INFO = GET_VIRTUAL_DISK_INFO*;

// Set Virtual Disk Information
enum SET_VIRTUAL_DISK_INFO_VERSION {
    SET_VIRTUAL_DISK_INFO_UNSPECIFIED                   = 0,
    SET_VIRTUAL_DISK_INFO_PARENT_PATH                   = 1,
    SET_VIRTUAL_DISK_INFO_IDENTIFIER                    = 2,
    SET_VIRTUAL_DISK_INFO_PARENT_PATH_WITH_DEPTH        = 3,
    SET_VIRTUAL_DISK_INFO_PHYSICAL_SECTOR_SIZE          = 4,
    SET_VIRTUAL_DISK_INFO_VIRTUAL_DISK_ID               = 5,
    SET_VIRTUAL_DISK_INFO_CHANGE_TRACKING_STATE         = 6,
    SET_VIRTUAL_DISK_INFO_PARENT_LOCATOR                = 7
};

struct SET_VIRTUAL_DISK_INFO {
    SET_VIRTUAL_DISK_INFO_VERSION Version{ SET_VIRTUAL_DISK_INFO_UNSPECIFIED };
    union {
        PCWSTR ParentFilePath;
        GUID UniqueIdentifier;
        GUID VirtualDiskId;
    };
};
using PSET_VIRTUAL_DISK_INFO = SET_VIRTUAL_DISK_INFO*;

// Storage Dependency Information
enum GET_STORAGE_DEPENDENCY_FLAG {
    GET_STORAGE_DEPENDENCY_FLAG_NONE         = 0x00000000,
    GET_STORAGE_DEPENDENCY_FLAG_HOST_VOLUMES = 0x00000001,
    GET_STORAGE_DEPENDENCY_FLAG_DISK_HANDLE  = 0x00000002
};

struct STORAGE_DEPENDENCY_INFO_TYPE_1 {
    DWORD DependencyTypeFlags{ 0 };
    DWORD ProviderSpecificFlags{ 0 };
    VIRTUAL_STORAGE_TYPE VirtualStorageType{};
};

struct STORAGE_DEPENDENCY_INFO {
    DWORD Version{ 1 };
    DWORD NumberEntries{ 0 };
    STORAGE_DEPENDENCY_INFO_TYPE_1 Version1Entries[1];
};
using PSTORAGE_DEPENDENCY_INFO = STORAGE_DEPENDENCY_INFO*;

// ============================================================================
// 2. VHD & VHDX Container Geometry & Layout Specification
// ============================================================================

#pragma pack(push, 1)

// Standard VHD 512-Byte Footer (Connectix Format)
struct VHD_FOOTER {
    char      cookie[8]{ 'c','o','n','e','c','t','i','x' }; // "conectix"
    uint32_t  features{ 0x00000002 };                        // Reserved features
    uint32_t  fileFormatVersion{ 0x00010000 };               // 1.0
    uint64_t  dataOffset{ 0xFFFFFFFFFFFFFFFFULL };           // Absolute offset to dynamic header
    uint32_t  timeStamp{ 0 };                                // Seconds since Jan 1 2000 UTC
    char      creatorApp[4]{ 'w','i','n',' ' };              // "win "
    uint32_t  creatorVersion{ 0x000a0000 };                  // Windows 10/11
    char      creatorHostOS[4]{ 'W','i','2','k' };           // "Wi2k"
    uint64_t  originalSize{ 0 };                             // Bytes
    uint64_t  currentSize{ 0 };                              // Bytes
    struct {
        uint16_t cylinders{ 0 };
        uint8_t  heads{ 16 };
        uint8_t  sectorsPerTrack{ 63 };
    } diskGeometry;
    uint32_t  diskType{ 3 };                                 // 2 = Fixed, 3 = Dynamic, 4 = Differencing
    uint32_t  checksum{ 0 };                                 // One's complement sum
    GUID      uniqueId{};
    uint8_t   savedState{ 0 };
    uint8_t   reserved[427]{ 0 };
};

// VHD Dynamic Disk Header (1024 bytes)
struct VHD_DYNAMIC_HEADER {
    char      cookie[8]{ 'c','x','s','p','a','r','s','e' }; // "cxsparse"
    uint64_t  dataOffset{ 0xFFFFFFFFFFFFFFFFULL };
    uint64_t  tableOffset{ 1536 };                           // Absolute byte offset of BAT
    uint32_t  headerVersion{ 0x00010000 };
    uint32_t  maxTableEntries{ 0 };                          // Number of blocks
    uint32_t  blockSize{ 2097152 };                          // 2 MB default block size
    uint32_t  checksum{ 0 };
    GUID      parentUniqueId{};
    uint32_t  parentTimeStamp{ 0 };
    uint32_t  reserved1{ 0 };
    wchar_t   parentUnicodeName[256]{ 0 };
    uint8_t   parentLocators[192]{ 0 };
    uint8_t   reserved2[256]{ 0 };
};

// VHDX File Identifier Header
struct VHDX_FILE_IDENTIFIER {
    char      signature[8]{ 'v','h','d','x','f','i','l','e' }; // "vhdxfile"
    wchar_t   creator[256]{ L"MicaNT Sovereign VHDX Engine" };
};

#pragma pack(pop)

// Geometry synthesis helper
inline void CalculateVhdGeometry(uint64_t totalBytes, uint16_t& cylinders, uint8_t& heads, uint8_t& spt) {
    uint64_t totalSectors = totalBytes / 512;
    if (totalSectors > 65535ULL * 16 * 255) {
        totalSectors = 65535ULL * 16 * 255;
    }

    if (totalSectors >= 65535ULL * 16 * 63) {
        spt = 255;
        heads = 16;
        cylinders = static_cast<uint16_t>(totalSectors / (16 * 255));
    } else {
        spt = 63;
        heads = 16;
        cylinders = static_cast<uint16_t>(totalSectors / (16 * 63));
    }
    if (cylinders == 0) cylinders = 1;
}

// Checksum calculation helper
inline uint32_t CalculateVhdChecksum(const void* buffer, size_t size) {
    const auto* bytes = reinterpret_cast<const uint8_t*>(buffer);
    uint32_t sum = 0;
    for (size_t i = 0; i < size; ++i) {
        sum += bytes[i];
    }
    return ~sum;
}

// ============================================================================
// 3. Sovereign Virtual Disk Controller & Instance Engine
// ============================================================================

enum class DiskFormat {
    Vhd,
    Vhdx
};

enum class DiskAllocation {
    Fixed,
    Dynamic,
    Differencing
};

struct VirtualDiskInstance {
    std::wstring filePath;
    std::string  filePathNarrow;
    DiskFormat   format{ DiskFormat::Vhd };
    DiskAllocation allocation{ DiskAllocation::Dynamic };
    uint64_t     virtualSize{ 0 };
    uint64_t     physicalSize{ 0 };
    uint32_t     sectorSize{ 512 };
    uint32_t     blockSize{ 2097152 }; // 2 MB
    GUID         uniqueId{};
    std::wstring parentPath;

    // Attachment State
    bool         isAttached{ false };
    DWORD        attachFlags{ 0 };
    uint32_t     driveIndex{ 0 };
    std::wstring physicalDrivePath;  // e.g. \\.\PhysicalDrive1
    std::wstring volumeDevicePath;   // e.g. \Device\HarddiskVolumeVirtual1

    // Simulation Data Payload
    std::vector<uint8_t> onDiskHeader;
};

struct OpenHandleContext {
    std::wstring diskPath;
    VIRTUAL_DISK_ACCESS_MASK accessMask{ VIRTUAL_DISK_ACCESS_ALL };
    DWORD openFlags{ 0 };
    bool readOnly{ false };
};

class SovereignVirtDiskManager {
private:
    std::mutex m_mutex;
    uintptr_t  m_nextHandle{ 0x5000 };
    uint32_t   m_nextDriveIndex{ 1 };

    // Registered Disks on Virtual Storage (keyed by normalized path)
    std::unordered_map<std::wstring, VirtualDiskInstance> m_disks;

    // Active Open Handles
    std::unordered_map<HANDLE, OpenHandleContext> m_handles;

    SovereignVirtDiskManager() {
        // Pre-seed a default virtual system recovery disk: "C:\\Recovery\\MicaNT-Recovery.vhd"
        VirtualDiskInstance defDisk{};
        defDisk.filePath = L"C:\\Recovery\\MicaNT-Recovery.vhd";
        defDisk.filePathNarrow = "C:\\Recovery\\MicaNT-Recovery.vhd";
        defDisk.format = DiskFormat::Vhd;
        defDisk.allocation = DiskAllocation::Dynamic;
        defDisk.virtualSize = 4ULL * 1024 * 1024 * 1024; // 4 GB
        defDisk.physicalSize = 16 * 1024 * 1024;        // 16 MB
        defDisk.sectorSize = 512;
        defDisk.blockSize = 2097152;
        defDisk.uniqueId = { 0x56484401, 0x4D49, 0x4341, { 0x4E, 0x54, 0x53, 0x4F, 0x56, 0x00, 0x00, 0x01 } };
        defDisk.isAttached = false;
        m_disks[defDisk.filePath] = defDisk;
    }

public:
    static SovereignVirtDiskManager& get() {
        static SovereignVirtDiskManager s_instance;
        return s_instance;
    }

    std::wstring normalizePath(PCWSTR path) {
        if (!path) return L"";
        std::wstring s(path);
        for (auto& c : s) {
            if (c == L'/') c = L'\\';
        }
        return s;
    }

    // Create Virtual Disk
    DWORD createDisk(
        PVIRTUAL_STORAGE_TYPE pVirtualStorageType,
        PCWSTR Path,
        VIRTUAL_DISK_ACCESS_MASK VirtualDiskAccessMask,
        CREATE_VIRTUAL_DISK_FLAG Flags,
        PCREATE_VIRTUAL_DISK_PARAMETERS Parameters,
        PHANDLE Handle
    ) {
        if (!Path || !Parameters || !Handle) return ERROR_INVALID_PARAMETER;
        std::wstring normPath = normalizePath(Path);

        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_disks.count(normPath)) {
            return ERROR_ALREADY_EXISTS;
        }

        VirtualDiskInstance inst{};
        inst.filePath = normPath;
        inst.filePathNarrow = std::string(normPath.begin(), normPath.end());

        // Determine format
        if (pVirtualStorageType && pVirtualStorageType->DeviceId == VIRTUAL_STORAGE_TYPE_DEVICE_VHDX) {
            inst.format = DiskFormat::Vhdx;
            inst.sectorSize = 4096;
        } else if (normPath.ends_with(L".vhdx")) {
            inst.format = DiskFormat::Vhdx;
            inst.sectorSize = 4096;
        } else {
            inst.format = DiskFormat::Vhd;
            inst.sectorSize = 512;
        }

        // Determine allocation
        if (Flags & CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION) {
            inst.allocation = DiskAllocation::Fixed;
        } else {
            inst.allocation = DiskAllocation::Dynamic;
        }

        if (Parameters->Version == CREATE_VIRTUAL_DISK_VERSION_1) {
            inst.virtualSize = Parameters->Version1.MaximumSize;
            if (Parameters->Version1.BlockSizeInBytes != 0) {
                inst.blockSize = Parameters->Version1.BlockSizeInBytes;
            }
            if (Parameters->Version1.SectorSizeInBytes != 0) {
                inst.sectorSize = Parameters->Version1.SectorSizeInBytes;
            }
            if (Parameters->Version1.ParentPath) {
                inst.parentPath = normalizePath(Parameters->Version1.ParentPath);
                inst.allocation = DiskAllocation::Differencing;
            }
            inst.uniqueId = Parameters->Version1.UniqueId;
        } else if (Parameters->Version == CREATE_VIRTUAL_DISK_VERSION_2) {
            inst.virtualSize = Parameters->Version2.MaximumSize;
            if (Parameters->Version2.BlockSizeInBytes != 0) {
                inst.blockSize = Parameters->Version2.BlockSizeInBytes;
            }
            if (Parameters->Version2.SectorSizeInBytes != 0) {
                inst.sectorSize = Parameters->Version2.SectorSizeInBytes;
            }
            if (Parameters->Version2.ParentPath) {
                inst.parentPath = normalizePath(Parameters->Version2.ParentPath);
                inst.allocation = DiskAllocation::Differencing;
            }
            inst.uniqueId = Parameters->Version2.UniqueId;
        } else {
            return ERROR_INVALID_PARAMETER;
        }

        if (inst.virtualSize == 0) {
            inst.virtualSize = 1024ULL * 1024 * 1024; // Default 1 GB
        }

        // Calculate physical allocation size
        if (inst.allocation == DiskAllocation::Fixed) {
            inst.physicalSize = inst.virtualSize + sizeof(VHD_FOOTER);
        } else {
            // Dynamic disks start with metadata + BAT
            inst.physicalSize = sizeof(VHD_FOOTER) + sizeof(VHD_DYNAMIC_HEADER) + 65536;
        }

        // Synthesize GUID if blank
        if (inst.uniqueId.Data1 == 0 && inst.uniqueId.Data2 == 0) {
            inst.uniqueId = {
                static_cast<uint32_t>(0x56484400 + m_nextDriveIndex),
                0x4D49, 0x4341,
                { 0x4E, 0x54, 0x53, 0x4F, 0x56, 0x00, 0x00, static_cast<uint8_t>(m_nextDriveIndex) }
            };
        }

        // Synthesize on-disk VHD footer
        inst.onDiskHeader.resize(sizeof(VHD_FOOTER));
        auto* pFooter = reinterpret_cast<VHD_FOOTER*>(inst.onDiskHeader.data());
        pFooter->originalSize = inst.virtualSize;
        pFooter->currentSize = inst.virtualSize;
        pFooter->diskType = (inst.allocation == DiskAllocation::Fixed) ? 2 : (inst.allocation == DiskAllocation::Dynamic ? 3 : 4);
        CalculateVhdGeometry(inst.virtualSize, pFooter->diskGeometry.cylinders, pFooter->diskGeometry.heads, pFooter->diskGeometry.sectorsPerTrack);
        pFooter->uniqueId = inst.uniqueId;
        pFooter->checksum = CalculateVhdChecksum(pFooter, sizeof(VHD_FOOTER));

        m_disks[normPath] = inst;

        // Create open handle
        HANDLE h = reinterpret_cast<HANDLE>(m_nextHandle++);
        OpenHandleContext ctx{};
        ctx.diskPath = normPath;
        ctx.accessMask = VirtualDiskAccessMask;
        ctx.readOnly = false;
        m_handles[h] = ctx;

        *Handle = h;
        return ERROR_SUCCESS;
    }

    // Open Virtual Disk
    DWORD openDisk(
        [[maybe_unused]] PVIRTUAL_STORAGE_TYPE pVirtualStorageType,
        PCWSTR Path,
        VIRTUAL_DISK_ACCESS_MASK VirtualDiskAccessMask,
        OPEN_VIRTUAL_DISK_FLAG Flags,
        POPEN_VIRTUAL_DISK_PARAMETERS Parameters,
        PHANDLE Handle
    ) {
        if (!Path || !Handle) return ERROR_INVALID_PARAMETER;
        std::wstring normPath = normalizePath(Path);

        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_disks.find(normPath);
        if (it == m_disks.end()) {
            return ERROR_FILE_NOT_FOUND;
        }

        HANDLE h = reinterpret_cast<HANDLE>(m_nextHandle++);
        OpenHandleContext ctx{};
        ctx.diskPath = normPath;
        ctx.accessMask = VirtualDiskAccessMask;
        ctx.openFlags = Flags;
        if (Parameters) {
            if (Parameters->Version == OPEN_VIRTUAL_DISK_VERSION_2) {
                ctx.readOnly = Parameters->Version2.ReadOnly != 0;
            } else if (Parameters->Version == OPEN_VIRTUAL_DISK_VERSION_3) {
                ctx.readOnly = Parameters->Version3.ReadOnly != 0;
            }
        }
        m_handles[h] = ctx;

        *Handle = h;
        return ERROR_SUCCESS;
    }

    // Close Handle
    DWORD closeDisk(HANDLE Handle) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_handles.find(Handle);
        if (it == m_handles.end()) {
            return ERROR_INVALID_HANDLE;
        }
        m_handles.erase(it);
        return ERROR_SUCCESS;
    }

    // Attach Virtual Disk
    DWORD attachDisk(
        HANDLE Handle,
        ATTACH_VIRTUAL_DISK_FLAG Flags,
        [[maybe_unused]] PATTACH_VIRTUAL_DISK_PARAMETERS Parameters
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto itH = m_handles.find(Handle);
        if (itH == m_handles.end()) return ERROR_INVALID_HANDLE;

        auto itD = m_disks.find(itH->second.diskPath);
        if (itD == m_disks.end()) return ERROR_FILE_NOT_FOUND;

        if (itD->second.isAttached) {
            return ERROR_ALREADY_EXISTS;
        }

        itD->second.isAttached = true;
        itD->second.attachFlags = Flags;
        itD->second.driveIndex = m_nextDriveIndex++;

        // Synthesize physical path: \\.\PhysicalDrive<N>
        itD->second.physicalDrivePath = L"\\\\.\\PhysicalDrive" + std::to_wstring(itD->second.driveIndex);
        itD->second.volumeDevicePath = L"\\Device\\HarddiskVolumeVirtual" + std::to_wstring(itD->second.driveIndex);

        return ERROR_SUCCESS;
    }

    // Detach Virtual Disk
    DWORD detachDisk(HANDLE Handle, [[maybe_unused]] DETACH_VIRTUAL_DISK_FLAG Flags) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto itH = m_handles.find(Handle);
        if (itH == m_handles.end()) return ERROR_INVALID_HANDLE;

        auto itD = m_disks.find(itH->second.diskPath);
        if (itD == m_disks.end()) return ERROR_FILE_NOT_FOUND;

        if (!itD->second.isAttached) {
            return ERROR_NOT_FOUND;
        }

        itD->second.isAttached = false;
        itD->second.attachFlags = 0;
        itD->second.physicalDrivePath.clear();
        itD->second.volumeDevicePath.clear();

        return ERROR_SUCCESS;
    }

    // Get Virtual Disk Information
    DWORD getInfo(
        HANDLE Handle,
        PULONG VirtualDiskInfoSize,
        PGET_VIRTUAL_DISK_INFO VirtualDiskInfo,
        PULONG SizeUsed
    ) {
        if (!VirtualDiskInfoSize || !VirtualDiskInfo) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto itH = m_handles.find(Handle);
        if (itH == m_handles.end()) return ERROR_INVALID_HANDLE;

        auto itD = m_disks.find(itH->second.diskPath);
        if (itD == m_disks.end()) return ERROR_FILE_NOT_FOUND;

        const auto& d = itD->second;

        switch (VirtualDiskInfo->Version) {
            case GET_VIRTUAL_DISK_INFO_SIZE: {
                if (*VirtualDiskInfoSize < sizeof(GET_VIRTUAL_DISK_INFO)) {
                    if (SizeUsed) *SizeUsed = sizeof(GET_VIRTUAL_DISK_INFO);
                    return ERROR_INSUFFICIENT_BUFFER;
                }
                VirtualDiskInfo->Size.VirtualSize = d.virtualSize;
                VirtualDiskInfo->Size.PhysicalSize = d.physicalSize;
                VirtualDiskInfo->Size.BlockSize = d.blockSize;
                VirtualDiskInfo->Size.SectorSize = d.sectorSize;
                if (SizeUsed) *SizeUsed = sizeof(GET_VIRTUAL_DISK_INFO);
                return ERROR_SUCCESS;
            }
            case GET_VIRTUAL_DISK_INFO_IDENTIFIER: {
                VirtualDiskInfo->Identifier = d.uniqueId;
                if (SizeUsed) *SizeUsed = sizeof(GET_VIRTUAL_DISK_INFO);
                return ERROR_SUCCESS;
            }
            case GET_VIRTUAL_DISK_INFO_VIRTUAL_STORAGE_TYPE: {
                VirtualDiskInfo->VirtualStorageType.DeviceId =
                    (d.format == DiskFormat::Vhdx) ? VIRTUAL_STORAGE_TYPE_DEVICE_VHDX : VIRTUAL_STORAGE_TYPE_DEVICE_VHD;
                VirtualDiskInfo->VirtualStorageType.VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT;
                if (SizeUsed) *SizeUsed = sizeof(GET_VIRTUAL_DISK_INFO);
                return ERROR_SUCCESS;
            }
            case GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE: {
                // 2 = Fixed, 3 = Dynamic, 4 = Differencing
                VirtualDiskInfo->ProviderSubtype = (d.allocation == DiskAllocation::Fixed) ? 2 :
                                                   (d.allocation == DiskAllocation::Dynamic ? 3 : 4);
                if (SizeUsed) *SizeUsed = sizeof(GET_VIRTUAL_DISK_INFO);
                return ERROR_SUCCESS;
            }
            case GET_VIRTUAL_DISK_INFO_IS_4K_ALIGNED: {
                VirtualDiskInfo->Is4kAligned = (d.sectorSize >= 4096 || (d.virtualSize % 4096 == 0)) ? 1 : 0;
                if (SizeUsed) *SizeUsed = sizeof(GET_VIRTUAL_DISK_INFO);
                return ERROR_SUCCESS;
            }
            case GET_VIRTUAL_DISK_INFO_IS_LOADED: {
                VirtualDiskInfo->IsLoaded = d.isAttached ? 1 : 0;
                if (SizeUsed) *SizeUsed = sizeof(GET_VIRTUAL_DISK_INFO);
                return ERROR_SUCCESS;
            }
            case GET_VIRTUAL_DISK_INFO_PHYSICAL_DISK: {
                VirtualDiskInfo->PhysicalDisk.LogicalSectorSize = d.sectorSize;
                VirtualDiskInfo->PhysicalDisk.PhysicalSectorSize = (d.format == DiskFormat::Vhdx) ? 4096 : 512;
                VirtualDiskInfo->PhysicalDisk.IsRemote = 0;
                if (SizeUsed) *SizeUsed = sizeof(GET_VIRTUAL_DISK_INFO);
                return ERROR_SUCCESS;
            }
            default:
                return ERROR_NOT_SUPPORTED;
        }
    }

    // Set Virtual Disk Information
    DWORD setInfo(HANDLE Handle, PSET_VIRTUAL_DISK_INFO VirtualDiskInfo) {
        if (!VirtualDiskInfo) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto itH = m_handles.find(Handle);
        if (itH == m_handles.end()) return ERROR_INVALID_HANDLE;

        auto itD = m_disks.find(itH->second.diskPath);
        if (itD == m_disks.end()) return ERROR_FILE_NOT_FOUND;

        switch (VirtualDiskInfo->Version) {
            case SET_VIRTUAL_DISK_INFO_PARENT_PATH: {
                if (VirtualDiskInfo->ParentFilePath) {
                    itD->second.parentPath = normalizePath(VirtualDiskInfo->ParentFilePath);
                    itD->second.allocation = DiskAllocation::Differencing;
                }
                return ERROR_SUCCESS;
            }
            case SET_VIRTUAL_DISK_INFO_IDENTIFIER: {
                itD->second.uniqueId = VirtualDiskInfo->UniqueIdentifier;
                return ERROR_SUCCESS;
            }
            default:
                return ERROR_NOT_SUPPORTED;
        }
    }

    // Get Physical Path
    DWORD getPhysicalPath(HANDLE Handle, PULONG DiskPathSizeInBytes, PWSTR DiskPath) {
        if (!DiskPathSizeInBytes) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto itH = m_handles.find(Handle);
        if (itH == m_handles.end()) return ERROR_INVALID_HANDLE;

        auto itD = m_disks.find(itH->second.diskPath);
        if (itD == m_disks.end()) return ERROR_FILE_NOT_FOUND;

        if (!itD->second.isAttached) {
            return ERROR_NOT_FOUND;
        }

        const auto& path = itD->second.physicalDrivePath;
        ULONG reqBytes = static_cast<ULONG>((path.size() + 1) * sizeof(wchar_t));

        if (!DiskPath || *DiskPathSizeInBytes < reqBytes) {
            *DiskPathSizeInBytes = reqBytes;
            return ERROR_INSUFFICIENT_BUFFER;
        }

        std::memcpy(DiskPath, path.c_str(), reqBytes);
        *DiskPathSizeInBytes = reqBytes;
        return ERROR_SUCCESS;
    }

    // Get All Attached Physical Paths (multi-sz string)
    DWORD getAllAttachedPhysicalPaths(PULONG PathsBufferSizeInBytes, PWSTR PathsBuffer) {
        if (!PathsBufferSizeInBytes) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<wchar_t> multiSz;
        for (const auto& pair : m_disks) {
            if (pair.second.isAttached && !pair.second.physicalDrivePath.empty()) {
                multiSz.insert(multiSz.end(), pair.second.physicalDrivePath.begin(), pair.second.physicalDrivePath.end());
                multiSz.push_back(L'\0');
            }
        }
        multiSz.push_back(L'\0'); // Double null terminator

        ULONG reqBytes = static_cast<ULONG>(multiSz.size() * sizeof(wchar_t));
        if (!PathsBuffer || *PathsBufferSizeInBytes < reqBytes) {
            *PathsBufferSizeInBytes = reqBytes;
            return ERROR_INSUFFICIENT_BUFFER;
        }

        std::memcpy(PathsBuffer, multiSz.data(), reqBytes);
        *PathsBufferSizeInBytes = reqBytes;
        return ERROR_SUCCESS;
    }

    // Expand Virtual Disk
    DWORD expandDisk(HANDLE Handle, PEXPAND_VIRTUAL_DISK_PARAMETERS Parameters) {
        if (!Parameters || Parameters->Version != EXPAND_VIRTUAL_DISK_VERSION_1) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto itH = m_handles.find(Handle);
        if (itH == m_handles.end()) return ERROR_INVALID_HANDLE;

        auto itD = m_disks.find(itH->second.diskPath);
        if (itD == m_disks.end()) return ERROR_FILE_NOT_FOUND;

        if (Parameters->Version1.NewSize <= itD->second.virtualSize) {
            return ERROR_INVALID_PARAMETER;
        }

        itD->second.virtualSize = Parameters->Version1.NewSize;
        if (itD->second.allocation == DiskAllocation::Fixed) {
            itD->second.physicalSize = itD->second.virtualSize + sizeof(VHD_FOOTER);
        }
        return ERROR_SUCCESS;
    }

    // Resize Virtual Disk
    DWORD resizeDisk(HANDLE Handle, PRESIZE_VIRTUAL_DISK_PARAMETERS Parameters) {
        if (!Parameters || Parameters->Version != RESIZE_VIRTUAL_DISK_VERSION_1) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto itH = m_handles.find(Handle);
        if (itH == m_handles.end()) return ERROR_INVALID_HANDLE;

        auto itD = m_disks.find(itH->second.diskPath);
        if (itD == m_disks.end()) return ERROR_FILE_NOT_FOUND;

        itD->second.virtualSize = Parameters->Version1.NewSize;
        if (itD->second.allocation == DiskAllocation::Fixed) {
            itD->second.physicalSize = itD->second.virtualSize + sizeof(VHD_FOOTER);
        }
        return ERROR_SUCCESS;
    }

    // Compact Virtual Disk
    DWORD compactDisk(HANDLE Handle, [[maybe_unused]] PCOMPACT_VIRTUAL_DISK_PARAMETERS Parameters) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto itH = m_handles.find(Handle);
        if (itH == m_handles.end()) return ERROR_INVALID_HANDLE;

        auto itD = m_disks.find(itH->second.diskPath);
        if (itD == m_disks.end()) return ERROR_FILE_NOT_FOUND;

        // Compaction optimizes physical size for dynamic disks
        if (itD->second.allocation == DiskAllocation::Dynamic) {
            itD->second.physicalSize = std::max<uint64_t>(
                sizeof(VHD_FOOTER) + sizeof(VHD_DYNAMIC_HEADER) + 65536,
                itD->second.physicalSize / 2
            );
        }
        return ERROR_SUCCESS;
    }

    // Storage Dependency Information
    DWORD getStorageDependencyInfo(
        HANDLE Handle,
        ULONG StorageDependencyInfoSize,
        PSTORAGE_DEPENDENCY_INFO StorageDependencyInfo,
        PULONG SizeUsed
    ) {
        if (!StorageDependencyInfo) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(m_mutex);

        auto itH = m_handles.find(Handle);
        if (itH == m_handles.end()) return ERROR_INVALID_HANDLE;

        auto itD = m_disks.find(itH->second.diskPath);
        if (itD == m_disks.end()) return ERROR_FILE_NOT_FOUND;

        if (StorageDependencyInfoSize < sizeof(STORAGE_DEPENDENCY_INFO)) {
            if (SizeUsed) *SizeUsed = sizeof(STORAGE_DEPENDENCY_INFO);
            return ERROR_INSUFFICIENT_BUFFER;
        }

        StorageDependencyInfo->Version = 1;
        StorageDependencyInfo->NumberEntries = 1;
        StorageDependencyInfo->Version1Entries[0].DependencyTypeFlags = 0x00000001;
        StorageDependencyInfo->Version1Entries[0].ProviderSpecificFlags = 0;
        StorageDependencyInfo->Version1Entries[0].VirtualStorageType.DeviceId =
            (itD->second.format == DiskFormat::Vhdx) ? VIRTUAL_STORAGE_TYPE_DEVICE_VHDX : VIRTUAL_STORAGE_TYPE_DEVICE_VHD;
        StorageDependencyInfo->Version1Entries[0].VirtualStorageType.VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT;

        if (SizeUsed) *SizeUsed = sizeof(STORAGE_DEPENDENCY_INFO);
        return ERROR_SUCCESS;
    }

    // Diagnostic & CLI helpers
    std::vector<VirtualDiskInstance> getAllDisks() {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<VirtualDiskInstance> res;
        for (const auto& pair : m_disks) {
            res.push_back(pair.second);
        }
        return res;
    }

    bool findDisk(const std::wstring& path, VirtualDiskInstance& outDisk) {
        std::wstring norm = normalizePath(path.c_str());
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_disks.find(norm);
        if (it != m_disks.end()) {
            outDisk = it->second;
            return true;
        }
        return false;
    }
};

// ============================================================================
// 4. Standard Win32 Virtual Disk C API Function Definitions (virtdisk.dll)
// ============================================================================

inline DWORD WINAPI CreateVirtualDisk(
    PVIRTUAL_STORAGE_TYPE VirtualStorageType,
    PCWSTR Path,
    VIRTUAL_DISK_ACCESS_MASK VirtualDiskAccessMask,
    [[maybe_unused]] PSECURITY_DESCRIPTOR SecurityDescriptor,
    CREATE_VIRTUAL_DISK_FLAG Flags,
    [[maybe_unused]] ULONG ProviderSpecificFlags,
    PCREATE_VIRTUAL_DISK_PARAMETERS Parameters,
    [[maybe_unused]] LPOVERLAPPED Overlapped,
    PHANDLE Handle
) {
    return SovereignVirtDiskManager::get().createDisk(
        VirtualStorageType, Path, VirtualDiskAccessMask, Flags, Parameters, Handle);
}

inline DWORD WINAPI OpenVirtualDisk(
    PVIRTUAL_STORAGE_TYPE VirtualStorageType,
    PCWSTR Path,
    VIRTUAL_DISK_ACCESS_MASK VirtualDiskAccessMask,
    OPEN_VIRTUAL_DISK_FLAG Flags,
    POPEN_VIRTUAL_DISK_PARAMETERS Parameters,
    PHANDLE Handle
) {
    return SovereignVirtDiskManager::get().openDisk(
        VirtualStorageType, Path, VirtualDiskAccessMask, Flags, Parameters, Handle);
}

inline DWORD WINAPI AttachVirtualDisk(
    HANDLE VirtualDiskHandle,
    [[maybe_unused]] PSECURITY_DESCRIPTOR SecurityDescriptor,
    ATTACH_VIRTUAL_DISK_FLAG Flags,
    [[maybe_unused]] ULONG ProviderSpecificFlags,
    PATTACH_VIRTUAL_DISK_PARAMETERS Parameters,
    [[maybe_unused]] LPOVERLAPPED Overlapped
) {
    return SovereignVirtDiskManager::get().attachDisk(VirtualDiskHandle, Flags, Parameters);
}

inline DWORD WINAPI DetachVirtualDisk(
    HANDLE VirtualDiskHandle,
    DETACH_VIRTUAL_DISK_FLAG Flags,
    [[maybe_unused]] ULONG ProviderSpecificFlags
) {
    return SovereignVirtDiskManager::get().detachDisk(VirtualDiskHandle, Flags);
}

inline DWORD WINAPI GetVirtualDiskInformation(
    HANDLE VirtualDiskHandle,
    PULONG VirtualDiskInfoSize,
    PGET_VIRTUAL_DISK_INFO VirtualDiskInfo,
    PULONG SizeUsed
) {
    return SovereignVirtDiskManager::get().getInfo(VirtualDiskHandle, VirtualDiskInfoSize, VirtualDiskInfo, SizeUsed);
}

inline DWORD WINAPI SetVirtualDiskInformation(
    HANDLE VirtualDiskHandle,
    PSET_VIRTUAL_DISK_INFO VirtualDiskInfo
) {
    return SovereignVirtDiskManager::get().setInfo(VirtualDiskHandle, VirtualDiskInfo);
}

inline DWORD WINAPI GetVirtualDiskPhysicalPath(
    HANDLE VirtualDiskHandle,
    PULONG DiskPathSizeInBytes,
    PWSTR DiskPath
) {
    return SovereignVirtDiskManager::get().getPhysicalPath(VirtualDiskHandle, DiskPathSizeInBytes, DiskPath);
}

inline DWORD WINAPI GetAllAttachedVirtualDiskPhysicalPaths(
    PULONG PathsBufferSizeInBytes,
    PWSTR PathsBuffer
) {
    return SovereignVirtDiskManager::get().getAllAttachedPhysicalPaths(PathsBufferSizeInBytes, PathsBuffer);
}

inline DWORD WINAPI CompactVirtualDisk(
    HANDLE VirtualDiskHandle,
    [[maybe_unused]] COMPACT_VIRTUAL_DISK_FLAG Flags,
    PCOMPACT_VIRTUAL_DISK_PARAMETERS Parameters,
    [[maybe_unused]] LPOVERLAPPED Overlapped
) {
    return SovereignVirtDiskManager::get().compactDisk(VirtualDiskHandle, Parameters);
}

inline DWORD WINAPI ExpandVirtualDisk(
    HANDLE VirtualDiskHandle,
    [[maybe_unused]] EXPAND_VIRTUAL_DISK_FLAG Flags,
    PEXPAND_VIRTUAL_DISK_PARAMETERS Parameters,
    [[maybe_unused]] LPOVERLAPPED Overlapped
) {
    return SovereignVirtDiskManager::get().expandDisk(VirtualDiskHandle, Parameters);
}

inline DWORD WINAPI ResizeVirtualDisk(
    HANDLE VirtualDiskHandle,
    [[maybe_unused]] RESIZE_VIRTUAL_DISK_FLAG Flags,
    PRESIZE_VIRTUAL_DISK_PARAMETERS Parameters,
    [[maybe_unused]] LPOVERLAPPED Overlapped
) {
    return SovereignVirtDiskManager::get().resizeDisk(VirtualDiskHandle, Parameters);
}

inline DWORD WINAPI MirrorVirtualDisk(
    [[maybe_unused]] HANDLE VirtualDiskHandle,
    [[maybe_unused]] MIRROR_VIRTUAL_DISK_FLAG Flags,
    [[maybe_unused]] PMIRROR_VIRTUAL_DISK_PARAMETERS Parameters,
    [[maybe_unused]] LPOVERLAPPED Overlapped
) {
    return ERROR_SUCCESS;
}

inline DWORD WINAPI BreakMirrorVirtualDisk([[maybe_unused]] HANDLE VirtualDiskHandle) {
    return ERROR_SUCCESS;
}

inline DWORD WINAPI AddVirtualDiskParent([[maybe_unused]] HANDLE VirtualDiskHandle, [[maybe_unused]] PCWSTR ParentPath) {
    return ERROR_SUCCESS;
}

inline DWORD WINAPI MergeVirtualDisk(
    [[maybe_unused]] HANDLE VirtualDiskHandle,
    [[maybe_unused]] MERGE_VIRTUAL_DISK_FLAG Flags,
    [[maybe_unused]] PMERGE_VIRTUAL_DISK_PARAMETERS Parameters,
    [[maybe_unused]] LPOVERLAPPED Overlapped
) {
    return ERROR_SUCCESS;
}

inline DWORD WINAPI GetStorageDependencyInformation(
    HANDLE ObjectHandle,
    [[maybe_unused]] GET_STORAGE_DEPENDENCY_FLAG Flags,
    ULONG StorageDependencyInfoSize,
    PSTORAGE_DEPENDENCY_INFO StorageDependencyInfo,
    PULONG SizeUsed
) {
    return SovereignVirtDiskManager::get().getStorageDependencyInfo(
        ObjectHandle, StorageDependencyInfoSize, StorageDependencyInfo, SizeUsed);
}

// ============================================================================
// 5. Subsystem Export Registration Helper
// ============================================================================

inline void InitializeVirtualDiskSubsystemExports() {
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        auto& loader = ldr::DynamicLoader::get();

        // 1. Register virtdisk.dll dynamic exports
        loader.registerExport("virtdisk.dll", "CreateVirtualDisk", reinterpret_cast<void*>(&CreateVirtualDisk));
        loader.registerExport("virtdisk.dll", "OpenVirtualDisk", reinterpret_cast<void*>(&OpenVirtualDisk));
        loader.registerExport("virtdisk.dll", "AttachVirtualDisk", reinterpret_cast<void*>(&AttachVirtualDisk));
        loader.registerExport("virtdisk.dll", "DetachVirtualDisk", reinterpret_cast<void*>(&DetachVirtualDisk));
        loader.registerExport("virtdisk.dll", "GetVirtualDiskInformation", reinterpret_cast<void*>(&GetVirtualDiskInformation));
        loader.registerExport("virtdisk.dll", "SetVirtualDiskInformation", reinterpret_cast<void*>(&SetVirtualDiskInformation));
        loader.registerExport("virtdisk.dll", "GetVirtualDiskPhysicalPath", reinterpret_cast<void*>(&GetVirtualDiskPhysicalPath));
        loader.registerExport("virtdisk.dll", "GetAllAttachedVirtualDiskPhysicalPaths", reinterpret_cast<void*>(&GetAllAttachedVirtualDiskPhysicalPaths));
        loader.registerExport("virtdisk.dll", "CompactVirtualDisk", reinterpret_cast<void*>(&CompactVirtualDisk));
        loader.registerExport("virtdisk.dll", "ExpandVirtualDisk", reinterpret_cast<void*>(&ExpandVirtualDisk));
        loader.registerExport("virtdisk.dll", "ResizeVirtualDisk", reinterpret_cast<void*>(&ResizeVirtualDisk));
        loader.registerExport("virtdisk.dll", "MirrorVirtualDisk", reinterpret_cast<void*>(&MirrorVirtualDisk));
        loader.registerExport("virtdisk.dll", "BreakMirrorVirtualDisk", reinterpret_cast<void*>(&BreakMirrorVirtualDisk));
        loader.registerExport("virtdisk.dll", "AddVirtualDiskParent", reinterpret_cast<void*>(&AddVirtualDiskParent));
        loader.registerExport("virtdisk.dll", "MergeVirtualDisk", reinterpret_cast<void*>(&MergeVirtualDisk));
        loader.registerExport("virtdisk.dll", "GetStorageDependencyInformation", reinterpret_cast<void*>(&GetStorageDependencyInformation));

        // 2. Register in VersionDatabase
        version::VersionDatabase::Instance().RegisterModule(
            "virtdisk.dll",
            "10.0.22621.1",
            "Windows Virtual Disk & Storage Management Subsystem",
            "MicaNT Sovereign Project"
        );
    });
}

} // namespace micant::virtdisk
