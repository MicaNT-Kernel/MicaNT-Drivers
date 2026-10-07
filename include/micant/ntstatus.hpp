#pragma once

#include <cstdint>
#include <string_view>

namespace micant {

/**
 * @brief Standard Windows NT Status Code (NTSTATUS) representation.
 * 32-bit value structured as:
 *   Bits 31-30: Severity (00 = Success, 01 = Info, 10 = Warning, 11 = Error)
 *   Bit 29: Customer / Reserved
 *   Bit 28: Reserved
 *   Bits 27-16: Facility code
 *   Bits 15-0: Status code
 */
enum class NtStatus : uint32_t {
    // 0x00000000 - Success
    Success                          = 0x00000000,
    Wait0                            = 0x00000000,
    Wait1                            = 0x00000001,
    Wait2                            = 0x00000002,
    Wait3                            = 0x00000003,
    Wait63                           = 0x0000003F,
    Abandoned                        = 0x00000080,
    UserApc                          = 0x000000C0,
    Timeout                          = 0x00000102,
    Pending                          = 0x00000103,

    // 0x80000000 - Warnings / Info
    DatatypeMisalignment             = 0x80000002,
    BufferOverflow                   = 0x80000005,
    NoMoreFiles                      = 0x80000006,
    HandlesClosed                    = 0x8000000A,

    // 0xC0000000 - Errors
    Unsuccessful                     = 0xC0000001,
    NotImplemented                   = 0xC0000002,
    InvalidInfoClass                 = 0xC0000003,
    InfoLengthMismatch               = 0xC0000004,
    AccessViolation                  = 0xC0000005,
    InPageError                      = 0xC0000006,
    PagefileQuota                    = 0xC0000007,
    InvalidHandle                    = 0xC0000008,
    BadInitialStack                  = 0xC0000009,
    BadInitialPc                     = 0xC000000A,
    InvalidCid                       = 0xC000000B,
    InvalidParameter                 = 0xC000000D,
    NoSuchDevice                     = 0xC000000E,
    NoSuchFile                       = 0xC000000F,
    InvalidDeviceRequest             = 0xC0000010,
    EndOfFile                        = 0xC0000011,
    NoMemory                         = 0xC0000017,
    Conflict                         = 0xC0000018,
    InsufficientResources            = 0xC000009A,
    IllegalInstruction               = 0xC000001D,
    AccessDenied                     = 0xC0000022,
    BufferTooSmall                   = 0xC0000023,
    ObjectNameNotFound               = 0xC0000034,
    ObjectNameCollision              = 0xC0000035,
    ObjectPathNotFound               = 0xC000003A,
    ObjectPathSyntaxBad              = 0xC000003B,
    SectionTooBig                    = 0xC0000040,
    PortConnectionRefused            = 0xC0000041,
    ServerNotRunning                 = 0xC0000042,
    SharingViolation                 = 0xC0000043,
    NoSuchProcess                    = 0xC0000043,
    QuotaExceeded                    = 0xC0000044,
    ProcessIsTerminating             = 0xC000010A,
    PrivilegeNotHeld                 = 0xC0000061,
    ProcedureNotFound                = 0xC000007A,
    FileIsADirectory                 = 0xC00000BA,
    DirectoryNotEmpty                = 0xC0000101,
    NotADirectory                    = 0xC0000103,
    DevicePowerFailure               = 0xC000009E,
    DeviceNotReady                   = 0xC00000A3,
    DiskFull                         = 0xC000007F,
    UnrecognizedVolume               = 0xC00000DB,
    InvalidParameter1                = 0xC00000EF,
    InvalidParameter2                = 0xC00000F0,
    InvalidParameter3                = 0xC00000F1,
    MailslotNotFound                 = 0xC0000055,
    PipeNotAvailable                 = 0xC00000AC,
    PipeBusy                         = 0xC00000AD,
    PipeDisconnected                 = 0xC00000B0,
    PipeClosing                      = 0xC00000B1,
    PipeConnected                    = 0xC00000B2,
    PipeListening                    = 0xC00000B3,
    PipeBroken                       = 0xC000014B,
    VolumeNotMounted                 = 0xC0000078,
    VolumeTooSmall                   = 0xC0000287,
    DeviceError                      = 0xC00000E0,
    FileCorrupted                    = 0xC0000102,
    Cancelled                        = 0xC0000120,

    // Security, Authentication & SAM Subsystem Codes
    UserExists                       = 0xC0000063,
    NoSuchUser                       = 0xC0000064,
    WrongPassword                    = 0xC000006A,
    LogonFailure                     = 0xC000006D,
    AccountRestriction               = 0xC000006E,
    PasswordExpired                  = 0xC0000071,
    AccountDisabled                  = 0xC0000072,
    NoSuchAlias                      = 0xC0000073,
    MemberInAlias                    = 0xC0000075,
    MemberNotInAlias                 = 0xC0000076,
    NoSuchLogonSession               = 0xC00000EE,
    LogonTypeNotGranted              = 0xC000015B,
    AccountLockedOut                 = 0xC0000234
};

// ============================================================================
// Standard NTSTATUS Integral Codes (32-bit signed NT-style constants)
// ============================================================================
using NTSTATUS = int32_t;
inline constexpr NTSTATUS STATUS_SUCCESS                = 0x00000000;
inline constexpr NTSTATUS STATUS_UNSUCCESSFUL           = static_cast<NTSTATUS>(0xC0000001);
inline constexpr NTSTATUS STATUS_NOT_IMPLEMENTED        = static_cast<NTSTATUS>(0xC0000002);
inline constexpr NTSTATUS STATUS_INVALID_HANDLE         = static_cast<NTSTATUS>(0xC0000008);
inline constexpr NTSTATUS STATUS_INVALID_PARAMETER      = static_cast<NTSTATUS>(0xC000000D);
inline constexpr NTSTATUS STATUS_ACCESS_DENIED          = static_cast<NTSTATUS>(0xC0000022);
inline constexpr NTSTATUS STATUS_BUFFER_TOO_SMALL       = static_cast<NTSTATUS>(0xC0000023);
inline constexpr NTSTATUS STATUS_OBJECT_NAME_NOT_FOUND  = static_cast<NTSTATUS>(0xC0000034);
inline constexpr NTSTATUS STATUS_OBJECT_NAME_COLLISION  = static_cast<NTSTATUS>(0xC0000035);
inline constexpr NTSTATUS STATUS_NOT_SUPPORTED          = static_cast<NTSTATUS>(0xC00000BB);
inline constexpr NTSTATUS STATUS_USER_EXISTS            = static_cast<NTSTATUS>(0xC0000063);
inline constexpr NTSTATUS STATUS_NO_SUCH_USER           = static_cast<NTSTATUS>(0xC0000064);
inline constexpr NTSTATUS STATUS_WRONG_PASSWORD         = static_cast<NTSTATUS>(0xC000006A);
inline constexpr NTSTATUS STATUS_LOGON_FAILURE          = static_cast<NTSTATUS>(0xC000006D);
inline constexpr NTSTATUS STATUS_ACCOUNT_RESTRICTION    = static_cast<NTSTATUS>(0xC000006E);
inline constexpr NTSTATUS STATUS_PASSWORD_EXPIRED       = static_cast<NTSTATUS>(0xC0000071);
inline constexpr NTSTATUS STATUS_ACCOUNT_DISABLED       = static_cast<NTSTATUS>(0xC0000072);
inline constexpr NTSTATUS STATUS_NO_SUCH_ALIAS          = static_cast<NTSTATUS>(0xC0000073);
inline constexpr NTSTATUS STATUS_MEMBER_IN_ALIAS        = static_cast<NTSTATUS>(0xC0000075);
inline constexpr NTSTATUS STATUS_MEMBER_NOT_IN_ALIAS    = static_cast<NTSTATUS>(0xC0000076);
inline constexpr NTSTATUS STATUS_NO_SUCH_LOGON_SESSION  = static_cast<NTSTATUS>(0xC00000EE);
inline constexpr NTSTATUS STATUS_LOGON_TYPE_NOT_GRANTED = static_cast<NTSTATUS>(0xC000015B);
inline constexpr NTSTATUS STATUS_INSUFFICIENT_RESOURCES = static_cast<NTSTATUS>(0xC000009A);
inline constexpr NTSTATUS STATUS_ACCOUNT_LOCKED_OUT     = static_cast<NTSTATUS>(0xC0000234);
inline constexpr NTSTATUS STATUS_NO_MEMORY              = static_cast<NTSTATUS>(0xC0000017);
inline constexpr NTSTATUS STATUS_NOT_FOUND              = static_cast<NTSTATUS>(0xC0000225);
inline constexpr NTSTATUS STATUS_PENDING                = static_cast<NTSTATUS>(0x00000103);
inline constexpr NTSTATUS STATUS_NO_MORE_ENTRIES        = static_cast<NTSTATUS>(0x8000001A);
inline constexpr NTSTATUS STATUS_DATA_ERROR             = static_cast<NTSTATUS>(0xC000003E);
inline constexpr NTSTATUS STATUS_DEVICE_POWER_FAILURE   = static_cast<NTSTATUS>(0xC000009E);
inline constexpr NTSTATUS STATUS_INVALID_DEVICE_STATE   = static_cast<NTSTATUS>(0xC0000184);
inline constexpr NTSTATUS STATUS_NO_SUCH_DEVICE         = static_cast<NTSTATUS>(0xC000000E);
inline constexpr NTSTATUS STATUS_TIMEOUT                = static_cast<NTSTATUS>(0x00000102);

[[nodiscard]] constexpr NtStatus STATUS_WAIT_N(uint32_t index) noexcept {
    return static_cast<NtStatus>(static_cast<uint32_t>(NtStatus::Wait0) + index);
}

// Standard NT macro semantics evaluated constexpr
[[nodiscard]] constexpr bool NT_SUCCESS(NtStatus status) noexcept {
    return static_cast<int32_t>(status) >= 0;
}

[[nodiscard]] constexpr bool NT_SUCCESS(int32_t status) noexcept {
    return status >= 0;
}

[[nodiscard]] constexpr bool NT_INFORMATION(NtStatus status) noexcept {
    return (static_cast<uint32_t>(status) >> 30) == 1;
}

[[nodiscard]] constexpr bool NT_WARNING(NtStatus status) noexcept {
    return (static_cast<uint32_t>(status) >> 30) == 2;
}

[[nodiscard]] constexpr bool NT_ERROR(NtStatus status) noexcept {
    return (static_cast<uint32_t>(status) >> 30) == 3;
}

[[nodiscard]] constexpr std::string_view NtStatusToString(NtStatus status) noexcept {
    switch (status) {
        case NtStatus::Success: return "STATUS_SUCCESS";
        case NtStatus::Timeout: return "STATUS_TIMEOUT";
        case NtStatus::Pending: return "STATUS_PENDING";
        case NtStatus::DatatypeMisalignment: return "STATUS_DATATYPE_MISALIGNMENT";
        case NtStatus::BufferOverflow: return "STATUS_BUFFER_OVERFLOW";
        case NtStatus::NoMoreFiles: return "STATUS_NO_MORE_FILES";
        case NtStatus::Unsuccessful: return "STATUS_UNSUCCESSFUL";
        case NtStatus::NotImplemented: return "STATUS_NOT_IMPLEMENTED";
        case NtStatus::AccessViolation: return "STATUS_ACCESS_VIOLATION";
        case NtStatus::IllegalInstruction: return "STATUS_ILLEGAL_INSTRUCTION";
        case NtStatus::InvalidHandle: return "STATUS_INVALID_HANDLE";
        case NtStatus::InvalidParameter: return "STATUS_INVALID_PARAMETER";
        case NtStatus::NoSuchFile: return "STATUS_NO_SUCH_FILE";
        case NtStatus::NoMemory: return "STATUS_NO_MEMORY";
        case NtStatus::InsufficientResources: return "STATUS_INSUFFICIENT_RESOURCES";
        case NtStatus::AccessDenied: return "STATUS_ACCESS_DENIED";
        case NtStatus::BufferTooSmall: return "STATUS_BUFFER_TOO_SMALL";
        case NtStatus::ObjectNameNotFound: return "STATUS_OBJECT_NAME_NOT_FOUND";
        case NtStatus::ObjectNameCollision: return "STATUS_OBJECT_NAME_COLLISION";
        case NtStatus::ObjectPathNotFound: return "STATUS_OBJECT_PATH_NOT_FOUND";
        case NtStatus::ProcedureNotFound: return "STATUS_PROCEDURE_NOT_FOUND";
        case NtStatus::ProcessIsTerminating: return "STATUS_PROCESS_IS_TERMINATING";
        case NtStatus::DeviceNotReady: return "STATUS_DEVICE_NOT_READY";
        case NtStatus::DiskFull: return "STATUS_DISK_FULL";
        case NtStatus::UnrecognizedVolume: return "STATUS_UNRECOGNIZED_VOLUME";
        case NtStatus::MailslotNotFound: return "STATUS_MAILSLOT_NOT_FOUND";
        case NtStatus::PipeNotAvailable: return "STATUS_PIPE_NOT_AVAILABLE";
        case NtStatus::PipeBusy: return "STATUS_PIPE_BUSY";
        case NtStatus::PipeDisconnected: return "STATUS_PIPE_DISCONNECTED";
        case NtStatus::PipeClosing: return "STATUS_PIPE_CLOSING";
        case NtStatus::PipeConnected: return "STATUS_PIPE_CONNECTED";
        case NtStatus::PipeListening: return "STATUS_PIPE_LISTENING";
        case NtStatus::PipeBroken: return "STATUS_PIPE_BROKEN";
        case NtStatus::VolumeNotMounted: return "STATUS_VOLUME_NOT_MOUNTED";
        case NtStatus::VolumeTooSmall: return "STATUS_VOLUME_TOO_SMALL";
        case NtStatus::DeviceError: return "STATUS_DEVICE_DATA_ERROR";
        case NtStatus::FileCorrupted: return "STATUS_FILE_CORRUPT_ERROR";
        case NtStatus::Cancelled: return "STATUS_CANCELLED";
        default: return "STATUS_UNKNOWN";
    }
}

} // namespace micant
