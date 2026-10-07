#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include "ntstatus.hpp"
#include "ntdef.hpp"

namespace micant::fs {
class FileObject;
}

namespace micant::sys {

// Standard x86-64 NT System Service Numbers (SSNs)
// Aligned with Windows 10/11 x64 dispatch indices
inline constexpr uint32_t SSN_NtCreateFile               = 0x0055;
inline constexpr uint32_t SSN_NtOpenFile                 = 0x0033;
inline constexpr uint32_t SSN_NtReadFile                 = 0x0006;
inline constexpr uint32_t SSN_NtWriteFile                = 0x0008;
inline constexpr uint32_t SSN_NtDeviceIoControlFile       = 0x0007;
inline constexpr uint32_t SSN_NtClose                    = 0x000F;
inline constexpr uint32_t SSN_NtAllocateVirtualMemory    = 0x0018;
inline constexpr uint32_t SSN_NtFreeVirtualMemory        = 0x001E;
inline constexpr uint32_t SSN_NtProtectVirtualMemory     = 0x0050;
inline constexpr uint32_t SSN_NtQueryVirtualMemory       = 0x0023;
inline constexpr uint32_t SSN_NtCreateProcessEx          = 0x00B4;
inline constexpr uint32_t SSN_NtTerminateProcess         = 0x002C;
inline constexpr uint32_t SSN_NtCreateThreadEx           = 0x00BD;
inline constexpr uint32_t SSN_NtTerminateThread          = 0x0053;
inline constexpr uint32_t SSN_NtWaitForSingleObject      = 0x0004;
inline constexpr uint32_t SSN_NtQuerySystemInformation   = 0x0036;

// Synchronization & IOCP SSNs
inline constexpr uint32_t SSN_NtCreateEvent              = 0x0048;
inline constexpr uint32_t SSN_NtSetEvent                 = 0x004E;
inline constexpr uint32_t SSN_NtResetEvent               = 0x004F;
inline constexpr uint32_t SSN_NtCreateMutant             = 0x00B2;
inline constexpr uint32_t SSN_NtReleaseMutant            = 0x001D;
inline constexpr uint32_t SSN_NtCreateIoCompletion       = 0x0164;
inline constexpr uint32_t SSN_NtSetIoCompletion          = 0x0165;
inline constexpr uint32_t SSN_NtRemoveIoCompletion       = 0x0009;

// Multi-Object Wait & Execution Delay SSNs
inline constexpr uint32_t SSN_NtWaitForMultipleObjects   = 0x005A;
inline constexpr uint32_t SSN_NtDelayExecution           = 0x0034;

// Kernel Timer SSNs
inline constexpr uint32_t SSN_NtCreateTimer              = 0x0057;
inline constexpr uint32_t SSN_NtSetTimer                 = 0x0078;
inline constexpr uint32_t SSN_NtCancelTimer              = 0x0077;

// Power Management & Shutdown SSN
inline constexpr uint32_t SSN_NtShutdownSystem           = 0x0118;

// Named Pipes & Mailslots SSNs
inline constexpr uint32_t SSN_NtCreateNamedPipeFile       = 0x0091;
inline constexpr uint32_t SSN_NtCreateMailslotFile        = 0x0092;

// Configuration Manager (Registry) SSNs
inline constexpr uint32_t SSN_NtCreateKey                = 0x0029;
inline constexpr uint32_t SSN_NtOpenKey                  = 0x0012;
inline constexpr uint32_t SSN_NtQueryValueKey            = 0x0016;
inline constexpr uint32_t SSN_NtSetValueKey              = 0x0060;

// Security Reference Monitor SSNs
inline constexpr uint32_t SSN_NtOpenProcessToken         = 0x00BE;
inline constexpr uint32_t SSN_NtAccessCheck              = 0x0182;

// Advanced Local Procedure Call (ALPC) SSNs
inline constexpr uint32_t SSN_NtCreatePort               = 0x0093;
inline constexpr uint32_t SSN_NtConnectPort              = 0x0096;
inline constexpr uint32_t SSN_NtRequestWaitReplyPort     = 0x0022;

// Section & Memory Mapping SSNs
inline constexpr uint32_t SSN_NtCreateSection            = 0x004A;
inline constexpr uint32_t SSN_NtOpenSection              = 0x0037;
inline constexpr uint32_t SSN_NtMapViewOfSection         = 0x0028;
inline constexpr uint32_t SSN_NtUnmapViewOfSection       = 0x002A;

// File Information & Directory Query SSNs
inline constexpr uint32_t SSN_NtQueryInformationFile     = 0x0011;
inline constexpr uint32_t SSN_NtSetInformationFile       = 0x0027;
inline constexpr uint32_t SSN_NtQueryDirectoryFile       = 0x0035;

// Performance & Execution SSNs
inline constexpr uint32_t SSN_NtQueryPerformanceCounter  = 0x0031;
inline constexpr uint32_t SSN_NtYieldExecution           = 0x0046;
inline constexpr uint32_t SSN_NtQueryInformationProcess  = 0x0019;

/**
 * @brief Native NT Syscall Signatures in Modern C++23
 */

// Memory Management
NtStatus NtAllocateVirtualMemory(
    Handle processHandle,
    uintptr_t* baseAddress,
    uintptr_t zeroBits,
    size_t* regionSize,
    uint32_t allocationType,
    uint32_t protect
);

NtStatus NtFreeVirtualMemory(
    Handle processHandle,
    uintptr_t* baseAddress,
    size_t* regionSize,
    uint32_t freeType
);

NtStatus NtProtectVirtualMemory(
    Handle processHandle,
    uintptr_t* baseAddress,
    size_t* regionSize,
    uint32_t newProtect,
    uint32_t* oldProtect
);

// File & I/O
NtStatus NtCreateFile(
    Handle* fileHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    IoStatusBlock* ioStatusBlock,
    LargeInteger* allocationSize,
    uint32_t fileAttributes,
    uint32_t shareAccess,
    uint32_t createDisposition,
    uint32_t createOptions,
    void* eaBuffer,
    uint32_t eaLength
);

NtStatus NtOpenFile(
    Handle* fileHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    IoStatusBlock* ioStatusBlock,
    uint32_t shareAccess,
    uint32_t openOptions
);

NtStatus NtReadFile(
    Handle fileHandle,
    Handle event,
    void* apcRoutine,
    void* apcContext,
    IoStatusBlock* ioStatusBlock,
    void* buffer,
    uint32_t length,
    LargeInteger* byteOffset,
    uint32_t* key
);

NtStatus NtWriteFile(
    Handle fileHandle,
    Handle event,
    void* apcRoutine,
    void* apcContext,
    IoStatusBlock* ioStatusBlock,
    const void* buffer,
    uint32_t length,
    LargeInteger* byteOffset,
    uint32_t* key
);

NtStatus NtDeviceIoControlFile(
    Handle fileHandle,
    Handle event,
    void* apcRoutine,
    void* apcContext,
    IoStatusBlock* ioStatusBlock,
    uint32_t ioControlCode,
    const void* inputBuffer,
    uint32_t inputBufferLength,
    void* outputBuffer,
    uint32_t outputBufferLength
);

NtStatus NtCreateNamedPipeFile(
    Handle* fileHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    IoStatusBlock* ioStatusBlock,
    uint32_t shareAccess,
    uint32_t createDisposition,
    uint32_t createOptions,
    uint32_t namedPipeType,
    uint32_t readMode,
    uint32_t completionMode,
    uint32_t maximumInstances,
    uint32_t inboundQuota,
    uint32_t outboundQuota,
    LargeInteger* defaultTimeout
);

NtStatus NtCreateMailslotFile(
    Handle* fileHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    IoStatusBlock* ioStatusBlock,
    uint32_t createOptions,
    uint32_t mailslotQuota,
    uint32_t maxMessageSize,
    LargeInteger* readTimeout
);

NtStatus NtClose(Handle handle);

fs::FileObject* LookupKernelFileObject(Handle handle);

// Process & Thread
NtStatus NtTerminateProcess(
    Handle processHandle,
    NtStatus exitStatus
);

NtStatus NtWaitForSingleObject(
    Handle handle,
    bool alertable,
    LargeInteger* timeout
);

NtStatus NtWaitForMultipleObjects(
    uint32_t count,
    const Handle* handles,
    WaitType waitType,
    bool alertable,
    LargeInteger* timeout
);

NtStatus NtDelayExecution(
    bool alertable,
    const LargeInteger* interval
);

NtStatus NtShutdownSystem(
    uint32_t action
);

NtStatus NtCreateTimer(
    Handle* timerHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    uint32_t timerType
);

NtStatus NtSetTimer(
    Handle timerHandle,
    LargeInteger* dueTime,
    void* timerApcRoutine,
    void* timerContext,
    bool resumeTimer,
    uint32_t period,
    bool* previousState
);

NtStatus NtCancelTimer(
    Handle timerHandle,
    bool* currentSignaledState
);

NtStatus NtQuerySystemInformation(
    uint32_t systemInformationClass,
    void* systemInformation,
    uint32_t systemInformationLength,
    uint32_t* returnLength
);

// Section Management
NtStatus NtCreateSection(
    Handle* sectionHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    LargeInteger* maximumSize,
    uint32_t sectionPageProtection,
    uint32_t allocationAttributes,
    Handle fileHandle
);

NtStatus NtMapViewOfSection(
    Handle sectionHandle,
    Handle processHandle,
    uintptr_t* baseAddress,
    uintptr_t zeroBits,
    size_t commitSize,
    LargeInteger* sectionOffset,
    size_t* viewSize,
    uint32_t inheritDisposition,
    uint32_t allocationType,
    uint32_t win32Protect
);

NtStatus NtUnmapViewOfSection(
    Handle processHandle,
    uintptr_t baseAddress
);

// File Information & Directory Queries
NtStatus NtQueryInformationFile(
    Handle fileHandle,
    IoStatusBlock* ioStatusBlock,
    void* fileInformation,
    uint32_t length,
    FileInformationClass fileInformationClass
);

NtStatus NtSetInformationFile(
    Handle fileHandle,
    IoStatusBlock* ioStatusBlock,
    const void* fileInformation,
    uint32_t length,
    FileInformationClass fileInformationClass
);

NtStatus NtQueryDirectoryFile(
    Handle fileHandle,
    Handle event,
    void* apcRoutine,
    void* apcContext,
    IoStatusBlock* ioStatusBlock,
    void* fileInformation,
    uint32_t length,
    FileInformationClass fileInformationClass,
    bool returnSingleEntry,
    UnicodeString* fileName,
    bool restartScan
);

// Performance & Process Information
NtStatus NtQueryPerformanceCounter(
    LargeInteger* performanceCounter,
    LargeInteger* performanceFrequency
);

NtStatus NtYieldExecution();

NtStatus NtQueryInformationProcess(
    Handle processHandle,
    ProcessInformationClass processInformationClass,
    void* processInformation,
    uint32_t processInformationLength,
    uint32_t* returnLength
);

} // namespace micant::sys

