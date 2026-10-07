#pragma once

#include <cstdint>
#include <string_view>
#include <concepts>
#include "ntstatus.hpp"

// ============================================================================
// Cross-Platform Calling Conventions & Windows ABI Types
// ============================================================================
#ifndef _WIN32
  #ifndef __stdcall
    #define __stdcall
  #endif
  #ifndef __cdecl
    #define __cdecl
  #endif
  #ifndef __fastcall
    #define __fastcall
  #endif
  #ifndef WINAPI
    #define WINAPI
  #endif
  #ifndef CALLBACK
    #define CALLBACK
  #endif
  #ifndef NTAPI
    #define NTAPI
  #endif
  #ifndef APIENTRY
    #define APIENTRY
  #endif
  #ifndef VOID
    #define VOID void
  #endif

  #ifndef _BOOL_DEFINED
    #define _BOOL_DEFINED
    using BOOL = int32_t;
    using BOOLEAN = uint8_t;
    #ifndef TRUE
      inline constexpr BOOL TRUE = 1;
    #endif
    #ifndef FALSE
      inline constexpr BOOL FALSE = 0;
    #endif
  #endif

  inline int strncpy_s(char* dest, size_t destsz, const char* src, size_t count) {
      if (!dest || destsz == 0) return 22; // EINVAL
      if (!src) {
          dest[0] = '\0';
          return 22;
      }
      size_t n = 0;
      while (n < count && n < destsz - 1 && src[n] != '\0') {
          dest[n] = src[n];
          n++;
      }
      dest[n] = '\0';
      return 0;
  }
#else
  #ifndef WINAPI
    #define WINAPI __stdcall
  #endif
  #ifndef CALLBACK
    #define CALLBACK __stdcall
  #endif
  #ifndef NTAPI
    #define NTAPI __stdcall
  #endif
  #ifndef APIENTRY
    #define APIENTRY __stdcall
  #endif
#endif

namespace micant {

#ifndef _MICANT_BOOL_DEFINED
#define _MICANT_BOOL_DEFINED
using BOOL = int32_t;
using BOOLEAN = uint8_t;
#ifndef TRUE
inline constexpr BOOL TRUE = 1;
#endif
#ifndef FALSE
inline constexpr BOOL FALSE = 0;
#endif
#endif

using Handle = intptr_t;
inline constexpr Handle InvalidHandleValue = -1;

/**
 * @brief Standard NT counted Unicode string.
 * Length and MaximumLength are stored in bytes, not wchar_t count.
 */
struct UnicodeString {
    uint16_t length{0};         // Length in bytes, excluding null terminator
    uint16_t maximumLength{0};  // Total buffer allocation in bytes
    const wchar_t* buffer{nullptr};

    constexpr UnicodeString() = default;
    constexpr UnicodeString(const wchar_t* str) noexcept
        : buffer(str) {
        if (str) {
            size_t len = 0;
            while (str[len] != L'\0') ++len;
            length = static_cast<uint16_t>(len * sizeof(wchar_t));
            maximumLength = static_cast<uint16_t>((len + 1) * sizeof(wchar_t));
        }
    }

    [[nodiscard]] constexpr std::wstring_view view() const noexcept {
        if (!buffer || length == 0) return {};
        return std::wstring_view(buffer, length / sizeof(wchar_t));
    }
};

/**
 * @brief 64-bit QuadPart integer representation.
 */
union LargeInteger {
    struct {
        uint32_t lowPart;
        int32_t highPart;
    };
    struct {
        uint32_t lowPart;
        int32_t highPart;
    } u;
    int64_t quadPart{0};
};

/**
 * @brief Locally Unique Identifier (LUID).
 * 64-bit value guaranteed to be unique only on the local system.
 */
struct Luid {
    uint32_t lowPart{0};
    int32_t highPart{0};

    constexpr Luid() = default;
    constexpr Luid(uint32_t low, int32_t high) noexcept : lowPart(low), highPart(high) {}

    constexpr bool operator==(const Luid& other) const noexcept {
        return lowPart == other.lowPart && highPart == other.highPart;
    }
    constexpr bool operator!=(const Luid& other) const noexcept {
        return !(*this == other);
    }
    [[nodiscard]] constexpr uint64_t toUint64() const noexcept {
        return (static_cast<uint64_t>(static_cast<uint32_t>(highPart)) << 32) | lowPart;
    }
    [[nodiscard]] static constexpr Luid fromUint64(uint64_t val) noexcept {
        return Luid(static_cast<uint32_t>(val & 0xFFFFFFFF), static_cast<int32_t>((val >> 32) & 0xFFFFFFFF));
    }
};

struct LuidAndAttributes {
    Luid luid{};
    uint32_t attributes{0};
};

using LUID = Luid;

struct Guid {
    uint32_t Data1{0};
    uint16_t Data2{0};
    uint16_t Data3{0};
    uint8_t  Data4[8]{0};

    constexpr bool operator==(const Guid& other) const noexcept {
        if (Data1 != other.Data1 || Data2 != other.Data2 || Data3 != other.Data3) return false;
        for (int i = 0; i < 8; ++i) {
            if (Data4[i] != other.Data4[i]) return false;
        }
        return true;
    }
};

using GUID = Guid;
using UUID = Guid;

/**
 * @brief Client identifier (Unique Process ID and Thread ID).
 */
struct ClientId {
    Handle uniqueProcess{0};
    Handle uniqueThread{0};
};

inline constexpr uint32_t MAXIMUM_WAIT_OBJECTS = 64;

enum class WaitType : uint32_t {
    WaitAll = 0,
    WaitAny = 1
};

/**
 * @brief Standard NT Object Attributes for kernel object instantiation.
 */
struct ObjectAttributes {
    uint32_t length{sizeof(ObjectAttributes)};
    Handle rootDirectory{0};
    const UnicodeString* objectName{nullptr};
    uint32_t attributes{0};
    void* securityDescriptor{nullptr};
    void* securityQualityOfService{nullptr};
};

// Object attribute flags
inline constexpr uint32_t OBJ_INHERIT             = 0x00000002;
inline constexpr uint32_t OBJ_PERMANENT           = 0x00000010;
inline constexpr uint32_t OBJ_EXCLUSIVE           = 0x00000020;
inline constexpr uint32_t OBJ_CASE_INSENSITIVE     = 0x00000040;
inline constexpr uint32_t OBJ_OPENIF              = 0x00000080;
inline constexpr uint32_t OBJ_OPENLINK            = 0x00000100;
inline constexpr uint32_t OBJ_KERNEL_HANDLE       = 0x00000200;
inline constexpr uint32_t OBJ_FORCE_ACCESS_CHECK   = 0x00000400;

/**
 * @brief I/O Status Block for asynchronous I/O completion.
 */
struct IoStatusBlock {
    union {
        NtStatus status;
        void* pointer;
    };
    uintptr_t information{0};
};

/**
 * @brief Standard KUSER_SHARED_DATA memory region.
 * On 64-bit Windows, mapped at fixed virtual address 0x000000007FFE0000.
 * Read-only in userland, read/write in kernel.
 */
struct KUserSharedData {
    uint32_t tickCountLowDeprecated;
    uint32_t tickCountMultiplier;
    volatile uint32_t interruptTimeLow;
    volatile int32_t interruptTimeHigh1;
    volatile int32_t interruptTimeHigh2;
    volatile uint32_t systemTimeLow;
    volatile int32_t systemTimeHigh1;
    volatile int32_t systemTimeHigh2;
    volatile uint32_t timeZoneBiasLow;
    volatile int32_t timeZoneBiasHigh1;
    volatile int32_t timeZoneBiasHigh2;
    uint16_t imageNumberLow;
    uint16_t imageNumberHigh;
    wchar_t ntSystemRoot[260];
    uint32_t maxStackTraceDepth;
    uint32_t cryptoExponent;
    uint32_t timeZoneId;
    uint32_t largePageMinimum;
    uint32_t aitSamplingValue;
    uint32_t appCompatFlag;
    uint64_t rngSeedVersion;
    uint32_t globalValidationRunlevel;
    volatile int32_t timeZoneBiasStamp;
    uint32_t ntBuildNumber;
    uint32_t ntProductType;
    uint8_t productType;
    uint8_t nativeProcessorArchitecture;
    uint16_t ntMajorVersion;
    uint16_t ntMinorVersion;
    uint8_t processorFeatures[64];
};

inline constexpr uintptr_t UserSharedDataAddress = 0x7FFE0000ULL;

// ============================================================================
// File Information Classes & Structures
// ============================================================================

enum class FileInformationClass : uint32_t {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation = 3,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileInternalInformation = 6,
    FileEaInformation = 7,
    FileAccessInformation = 8,
    FileNameInformation = 9,
    FileRenameInformation = 10,
    FileLinkInformation = 11,
    FileNamesInformation = 12,
    FileDispositionInformation = 13,
    FilePositionInformation = 14,
    FileFullEaInformation = 15,
    FileModeInformation = 16,
    FileAlignmentInformation = 17,
    FileAllInformation = 18,
    FileAllocationInformation = 19,
    FileEndOfFileInformation = 20
};

struct FileBasicInformation {
    LargeInteger creationTime{};
    LargeInteger lastAccessTime{};
    LargeInteger lastWriteTime{};
    LargeInteger changeTime{};
    uint32_t fileAttributes{0};
};

struct FileStandardInformation {
    LargeInteger allocationSize{};
    LargeInteger endOfFile{};
    uint32_t numberOfLinks{1};
    bool deletePending{false};
    bool directory{false};
};

struct FilePositionInformation {
    LargeInteger currentByteOffset{};
};

struct FileEndOfFileInformation {
    LargeInteger endOfFile{};
};

struct FileBothDirInformation {
    uint32_t nextEntryOffset{0};
    uint32_t fileIndex{0};
    LargeInteger creationTime{};
    LargeInteger lastAccessTime{};
    LargeInteger lastWriteTime{};
    LargeInteger changeTime{};
    LargeInteger endOfFile{};
    LargeInteger allocationSize{};
    uint32_t fileAttributes{0};
    uint32_t fileNameLength{0};
    uint32_t eaSize{0};
    int8_t shortNameLength{0};
    wchar_t shortName[12]{};
    wchar_t fileName[260]{};
};

// ============================================================================
// Process Information Classes & Structures
// ============================================================================

enum class ProcessInformationClass : uint32_t {
    ProcessBasicInformation = 0,
    ProcessQuotaLimits = 1,
    ProcessIoCounters = 2,
    ProcessVmCounters = 3,
    ProcessTimes = 4,
    ProcessBasePriority = 5,
    ProcessRaisePriority = 6,
    ProcessDebugPort = 7,
    ProcessExceptionPort = 8,
    ProcessAccessToken = 9
};

struct ProcessBasicInformation {
    NtStatus exitStatus{NtStatus::Success};
    uintptr_t pebBaseAddress{0};
    uintptr_t affinityMask{0x0F};
    int32_t basePriority{8};
    Handle uniqueProcessId{0};
    Handle inheritedFromUniqueProcessId{0};
};

} // namespace micant
