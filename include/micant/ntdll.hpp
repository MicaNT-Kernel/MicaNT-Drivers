#pragma once

#include <cstdint>
#include <cstddef>
#include <string_view>
#include <span>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "dispatcher.hpp"
#include "heap.hpp"
#include "ldr.hpp"

namespace micant::ntdll {

// Re-export Heap API into ntdll namespace
using heap::RtlCreateHeap;
using heap::RtlAllocateHeap;
using heap::RtlFreeHeap;
using heap::RtlDestroyHeap;
using heap::RtlSizeHeap;
using heap::RtlReAllocateHeap;
using heap::HEAP_NO_SERIALIZE;
using heap::HEAP_GROWABLE;
using heap::HEAP_GENERATE_EXCEPTIONS;
using heap::HEAP_ZERO_MEMORY;
using heap::HEAP_REALLOC_IN_PLACE_ONLY;

// Re-export Loader API into ntdll namespace
using ldr::LdrInitializeThunk;
using ldr::LdrLoadDll;
using ldr::LdrGetProcedureAddress;
using ldr::DynamicLoader;

// Thread-local Userland TEB Context Pointer
inline thread_local ps::Teb* g_CurrentTeb = nullptr;

[[nodiscard]] inline ps::Teb* RtlGetCurrentTeb() noexcept {
    return g_CurrentTeb;
}

[[nodiscard]] inline ps::Peb* RtlGetCurrentPeb() noexcept {
    if (!g_CurrentTeb) return nullptr;
    return reinterpret_cast<ps::Peb*>(g_CurrentTeb->processEnvironmentBlock);
}

inline void RtlSetCurrentTeb(ps::Teb* teb) noexcept {
    g_CurrentTeb = teb;
}

// ============================================================================
// NTDLL Clean-Room System Call Thunks (All 33 KiSystemCall64 Services)
// ============================================================================

// 1. NtAllocateVirtualMemory (SSN: 0x0018)
inline NtStatus NtAllocateVirtualMemory(
    Handle processHandle,
    uintptr_t* baseAddress,
    uintptr_t zeroBits,
    size_t* regionSize,
    uint32_t allocationType,
    uint32_t protect
) {
    uint64_t stack[2] = { allocationType, protect };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtAllocateVirtualMemory,
        .arg1 = static_cast<uint64_t>(processHandle),
        .arg2 = reinterpret_cast<uint64_t>(baseAddress),
        .arg3 = zeroBits,
        .arg4 = reinterpret_cast<uint64_t>(regionSize),
        .stackArgs = stack,
        .stackArgCount = 2
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 2. NtFreeVirtualMemory (SSN: 0x001E)
inline NtStatus NtFreeVirtualMemory(
    Handle processHandle,
    uintptr_t* baseAddress,
    size_t* regionSize,
    uint32_t freeType
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtFreeVirtualMemory,
        .arg1 = static_cast<uint64_t>(processHandle),
        .arg2 = reinterpret_cast<uint64_t>(baseAddress),
        .arg3 = reinterpret_cast<uint64_t>(regionSize),
        .arg4 = freeType
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 3. NtClose (SSN: 0x000F)
inline NtStatus NtClose(Handle handle) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtClose,
        .arg1 = static_cast<uint64_t>(handle)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 4. NtTerminateProcess (SSN: 0x002C)
inline NtStatus NtTerminateProcess(Handle processHandle, NtStatus exitStatus) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtTerminateProcess,
        .arg1 = static_cast<uint64_t>(processHandle),
        .arg2 = static_cast<uint64_t>(exitStatus)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 5. NtWaitForSingleObject (SSN: 0x0004)
inline NtStatus NtWaitForSingleObject(Handle handle, bool alertable, LargeInteger* timeout) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtWaitForSingleObject,
        .arg1 = static_cast<uint64_t>(handle),
        .arg2 = alertable ? 1ULL : 0ULL,
        .arg3 = reinterpret_cast<uint64_t>(timeout)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 6. NtQuerySystemInformation (SSN: 0x0036)
inline NtStatus NtQuerySystemInformation(
    uint32_t systemInformationClass,
    void* systemInformation,
    uint32_t systemInformationLength,
    uint32_t* returnLength
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtQuerySystemInformation,
        .arg1 = systemInformationClass,
        .arg2 = reinterpret_cast<uint64_t>(systemInformation),
        .arg3 = systemInformationLength,
        .arg4 = reinterpret_cast<uint64_t>(returnLength)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 7. NtCreateEvent (SSN: 0x0048)
inline NtStatus NtCreateEvent(
    Handle* eventHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    uint32_t eventType,
    bool initialState
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtCreateEvent,
        .arg1 = reinterpret_cast<uint64_t>(eventHandle),
        .arg2 = desiredAccess,
        .arg3 = eventType,
        .arg4 = initialState ? 1ULL : 0ULL
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 8. NtSetEvent (SSN: 0x004E)
inline NtStatus NtSetEvent(Handle eventHandle, uint32_t* previousState = nullptr) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtSetEvent,
        .arg1 = static_cast<uint64_t>(eventHandle),
        .arg2 = reinterpret_cast<uint64_t>(previousState)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 9. NtResetEvent (SSN: 0x004F)
inline NtStatus NtResetEvent(Handle eventHandle, uint32_t* previousState = nullptr) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtResetEvent,
        .arg1 = static_cast<uint64_t>(eventHandle),
        .arg2 = reinterpret_cast<uint64_t>(previousState)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 10. NtCreateMutant (SSN: 0x00B2)
inline NtStatus NtCreateMutant(
    Handle* mutantHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    bool initialOwner
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtCreateMutant,
        .arg1 = reinterpret_cast<uint64_t>(mutantHandle),
        .arg2 = desiredAccess,
        .arg3 = initialOwner ? 1ULL : 0ULL,
        .arg4 = reinterpret_cast<uint64_t>(objectAttributes)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 11. NtReleaseMutant (SSN: 0x001D)
inline NtStatus NtReleaseMutant(Handle mutantHandle, int32_t* previousCount = nullptr) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtReleaseMutant,
        .arg1 = static_cast<uint64_t>(mutantHandle),
        .arg2 = reinterpret_cast<uint64_t>(previousCount)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 12. NtCreateIoCompletion (SSN: 0x0164)
inline NtStatus NtCreateIoCompletion(
    Handle* ioCompletionHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    uint32_t count
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtCreateIoCompletion,
        .arg1 = reinterpret_cast<uint64_t>(ioCompletionHandle),
        .arg2 = desiredAccess,
        .arg3 = reinterpret_cast<uint64_t>(objectAttributes),
        .arg4 = count
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 13. NtSetIoCompletion (SSN: 0x0165)
inline NtStatus NtSetIoCompletion(
    Handle ioCompletionHandle,
    uint64_t keyContext,
    uintptr_t apcContext,
    NtStatus ioStatus,
    uint32_t ioStatusInformation
) {
    uint64_t stack[1] = { ioStatusInformation };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtSetIoCompletion,
        .arg1 = static_cast<uint64_t>(ioCompletionHandle),
        .arg2 = keyContext,
        .arg3 = apcContext,
        .arg4 = static_cast<uint64_t>(ioStatus),
        .stackArgs = stack,
        .stackArgCount = 1
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 14. NtRemoveIoCompletion (SSN: 0x0009)
inline NtStatus NtRemoveIoCompletion(
    Handle ioCompletionHandle,
    uint64_t* keyContext,
    uintptr_t* apcContext,
    IoStatusBlock* ioStatusBlock,
    LargeInteger* timeout
) {
    uint64_t stack[1] = { reinterpret_cast<uint64_t>(timeout) };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtRemoveIoCompletion,
        .arg1 = static_cast<uint64_t>(ioCompletionHandle),
        .arg2 = reinterpret_cast<uint64_t>(keyContext),
        .arg3 = reinterpret_cast<uint64_t>(apcContext),
        .arg4 = reinterpret_cast<uint64_t>(ioStatusBlock),
        .stackArgs = stack,
        .stackArgCount = 1
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 15. NtOpenKey (SSN: 0x0012)
inline NtStatus NtOpenKey(
    Handle* keyHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtOpenKey,
        .arg1 = reinterpret_cast<uint64_t>(keyHandle),
        .arg2 = desiredAccess,
        .arg3 = reinterpret_cast<uint64_t>(objectAttributes)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 16. NtQueryValueKey (SSN: 0x0016)
inline NtStatus NtQueryValueKey(
    Handle keyHandle,
    UnicodeString* valueName,
    uint32_t keyValueInformationClass,
    void* keyValueInformation,
    size_t length,
    size_t* resultLength
) {
    uint64_t stack[2] = { length, reinterpret_cast<uint64_t>(resultLength) };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtQueryValueKey,
        .arg1 = static_cast<uint64_t>(keyHandle),
        .arg2 = reinterpret_cast<uint64_t>(valueName),
        .arg3 = keyValueInformationClass,
        .arg4 = reinterpret_cast<uint64_t>(keyValueInformation),
        .stackArgs = stack,
        .stackArgCount = 2
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 17. NtSetValueKey (SSN: 0x0060)
inline NtStatus NtSetValueKey(
    Handle keyHandle,
    UnicodeString* valueName,
    uint32_t titleIndex,
    uint32_t type,
    const void* data,
    uint32_t dataSize
) {
    uint64_t stack[2] = { reinterpret_cast<uint64_t>(data), dataSize };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtSetValueKey,
        .arg1 = static_cast<uint64_t>(keyHandle),
        .arg2 = reinterpret_cast<uint64_t>(valueName),
        .arg3 = titleIndex,
        .arg4 = type,
        .stackArgs = stack,
        .stackArgCount = 2
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 18. NtOpenProcessToken (SSN: 0x00BE)
inline NtStatus NtOpenProcessToken(
    Handle processHandle,
    uint32_t desiredAccess,
    Handle* tokenHandle
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtOpenProcessToken,
        .arg1 = static_cast<uint64_t>(processHandle),
        .arg2 = desiredAccess,
        .arg3 = reinterpret_cast<uint64_t>(tokenHandle)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 19. NtAccessCheck (SSN: 0x0182)
inline NtStatus NtAccessCheck(
    void* securityDescriptor,
    Handle clientToken,
    uint32_t desiredAccess,
    uint32_t* grantedAccess,
    NtStatus* accessStatus = nullptr
) {
    uint64_t stack[1] = { reinterpret_cast<uint64_t>(accessStatus) };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtAccessCheck,
        .arg1 = reinterpret_cast<uint64_t>(securityDescriptor),
        .arg2 = static_cast<uint64_t>(clientToken),
        .arg3 = desiredAccess,
        .arg4 = reinterpret_cast<uint64_t>(grantedAccess),
        .stackArgs = stack,
        .stackArgCount = 1
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 20. NtCreatePort (SSN: 0x0093)
inline NtStatus NtCreatePort(
    Handle* portHandle,
    ObjectAttributes* objectAttributes,
    uint32_t maxConnectionInfoLength = 0,
    uint32_t maxMessageLength = 256
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtCreatePort,
        .arg1 = reinterpret_cast<uint64_t>(portHandle),
        .arg2 = reinterpret_cast<uint64_t>(objectAttributes),
        .arg3 = maxConnectionInfoLength,
        .arg4 = maxMessageLength
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 21. NtConnectPort (SSN: 0x0096)
inline NtStatus NtConnectPort(
    Handle* portHandle,
    UnicodeString* portName,
    void* securityQos = nullptr,
    void* clientView = nullptr
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtConnectPort,
        .arg1 = reinterpret_cast<uint64_t>(portHandle),
        .arg2 = reinterpret_cast<uint64_t>(portName),
        .arg3 = reinterpret_cast<uint64_t>(securityQos),
        .arg4 = reinterpret_cast<uint64_t>(clientView)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 22. NtRequestWaitReplyPort (SSN: 0x0022)
inline NtStatus NtRequestWaitReplyPort(
    Handle portHandle,
    void* requestMessage,
    void* replyMessage
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtRequestWaitReplyPort,
        .arg1 = static_cast<uint64_t>(portHandle),
        .arg2 = reinterpret_cast<uint64_t>(requestMessage),
        .arg3 = reinterpret_cast<uint64_t>(replyMessage)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 23. NtCreateFile (SSN: 0x0055)
inline NtStatus NtCreateFile(
    Handle* fileHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    IoStatusBlock* ioStatusBlock,
    LargeInteger* allocationSize = nullptr,
    uint32_t fileAttributes = 0,
    uint32_t shareAccess = 0,
    uint32_t createDisposition = 1,
    uint32_t createOptions = 0,
    void* eaBuffer = nullptr,
    uint32_t eaLength = 0
) {
    uint64_t stack[7] = {
        reinterpret_cast<uint64_t>(allocationSize),
        fileAttributes,
        shareAccess,
        createDisposition,
        createOptions,
        reinterpret_cast<uint64_t>(eaBuffer),
        eaLength
    };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtCreateFile,
        .arg1 = reinterpret_cast<uint64_t>(fileHandle),
        .arg2 = desiredAccess,
        .arg3 = reinterpret_cast<uint64_t>(objectAttributes),
        .arg4 = reinterpret_cast<uint64_t>(ioStatusBlock),
        .stackArgs = stack,
        .stackArgCount = 7
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 24. NtOpenFile (SSN: 0x0033)
inline NtStatus NtOpenFile(
    Handle* fileHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    IoStatusBlock* ioStatusBlock,
    uint32_t shareAccess = 0,
    uint32_t openOptions = 0
) {
    uint64_t stack[2] = { shareAccess, openOptions };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtOpenFile,
        .arg1 = reinterpret_cast<uint64_t>(fileHandle),
        .arg2 = desiredAccess,
        .arg3 = reinterpret_cast<uint64_t>(objectAttributes),
        .arg4 = reinterpret_cast<uint64_t>(ioStatusBlock),
        .stackArgs = stack,
        .stackArgCount = 2
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 25. NtReadFile (SSN: 0x0006)
inline NtStatus NtReadFile(
    Handle fileHandle,
    Handle event,
    void* apcRoutine,
    void* apcContext,
    IoStatusBlock* ioStatusBlock,
    void* buffer,
    uint32_t length,
    LargeInteger* byteOffset = nullptr,
    uint32_t* key = nullptr
) {
    uint64_t stack[5] = {
        reinterpret_cast<uint64_t>(ioStatusBlock),
        reinterpret_cast<uint64_t>(buffer),
        length,
        reinterpret_cast<uint64_t>(byteOffset),
        reinterpret_cast<uint64_t>(key)
    };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtReadFile,
        .arg1 = static_cast<uint64_t>(fileHandle),
        .arg2 = static_cast<uint64_t>(event),
        .arg3 = reinterpret_cast<uint64_t>(apcRoutine),
        .arg4 = reinterpret_cast<uint64_t>(apcContext),
        .stackArgs = stack,
        .stackArgCount = 5
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 26. NtWriteFile (SSN: 0x0008)
inline NtStatus NtWriteFile(
    Handle fileHandle,
    Handle event,
    void* apcRoutine,
    void* apcContext,
    IoStatusBlock* ioStatusBlock,
    const void* buffer,
    uint32_t length,
    LargeInteger* byteOffset = nullptr,
    uint32_t* key = nullptr
) {
    uint64_t stack[5] = {
        reinterpret_cast<uint64_t>(ioStatusBlock),
        reinterpret_cast<uint64_t>(buffer),
        length,
        reinterpret_cast<uint64_t>(byteOffset),
        reinterpret_cast<uint64_t>(key)
    };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtWriteFile,
        .arg1 = static_cast<uint64_t>(fileHandle),
        .arg2 = static_cast<uint64_t>(event),
        .arg3 = reinterpret_cast<uint64_t>(apcRoutine),
        .arg4 = reinterpret_cast<uint64_t>(apcContext),
        .stackArgs = stack,
        .stackArgCount = 5
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 27. NtDeviceIoControlFile (SSN: 0x0007)
inline NtStatus NtDeviceIoControlFile(
    Handle fileHandle,
    Handle event,
    void* apcRoutine,
    void* apcContext,
    IoStatusBlock* ioStatusBlock,
    uint32_t ioControlCode,
    const void* inputBuffer = nullptr,
    uint32_t inputBufferLength = 0,
    void* outputBuffer = nullptr,
    uint32_t outputBufferLength = 0
) {
    uint64_t stack[6] = {
        reinterpret_cast<uint64_t>(ioStatusBlock),
        ioControlCode,
        reinterpret_cast<uint64_t>(inputBuffer),
        inputBufferLength,
        reinterpret_cast<uint64_t>(outputBuffer),
        outputBufferLength
    };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtDeviceIoControlFile,
        .arg1 = static_cast<uint64_t>(fileHandle),
        .arg2 = static_cast<uint64_t>(event),
        .arg3 = reinterpret_cast<uint64_t>(apcRoutine),
        .arg4 = reinterpret_cast<uint64_t>(apcContext),
        .stackArgs = stack,
        .stackArgCount = 6
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 28. NtWaitForMultipleObjects (SSN: 0x005A)
inline NtStatus NtWaitForMultipleObjects(
    uint32_t count,
    const Handle* handles,
    WaitType waitType,
    bool alertable,
    LargeInteger* timeout = nullptr
) {
    uint64_t stack[1] = { reinterpret_cast<uint64_t>(timeout) };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtWaitForMultipleObjects,
        .arg1 = count,
        .arg2 = reinterpret_cast<uint64_t>(handles),
        .arg3 = static_cast<uint64_t>(waitType),
        .arg4 = alertable ? 1ULL : 0ULL,
        .stackArgs = stack,
        .stackArgCount = 1
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 29. NtDelayExecution (SSN: 0x0034)
inline NtStatus NtDelayExecution(bool alertable, const LargeInteger* interval) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtDelayExecution,
        .arg1 = alertable ? 1ULL : 0ULL,
        .arg2 = reinterpret_cast<uint64_t>(interval)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 30. NtCreateTimer (SSN: 0x0057)
inline NtStatus NtCreateTimer(
    Handle* timerHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    uint32_t timerType
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtCreateTimer,
        .arg1 = reinterpret_cast<uint64_t>(timerHandle),
        .arg2 = desiredAccess,
        .arg3 = reinterpret_cast<uint64_t>(objectAttributes),
        .arg4 = timerType
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 31. NtSetTimer (SSN: 0x0078)
inline NtStatus NtSetTimer(
    Handle timerHandle,
    LargeInteger* dueTime,
    void* timerApcRoutine = nullptr,
    void* timerContext = nullptr,
    bool resumeTimer = false,
    uint32_t period = 0,
    bool* previousState = nullptr
) {
    uint64_t stack[3] = {
        resumeTimer ? 1ULL : 0ULL,
        period,
        reinterpret_cast<uint64_t>(previousState)
    };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtSetTimer,
        .arg1 = static_cast<uint64_t>(timerHandle),
        .arg2 = reinterpret_cast<uint64_t>(dueTime),
        .arg3 = reinterpret_cast<uint64_t>(timerApcRoutine),
        .arg4 = reinterpret_cast<uint64_t>(timerContext),
        .stackArgs = stack,
        .stackArgCount = 3
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 32. NtCancelTimer (SSN: 0x0077)
inline NtStatus NtCancelTimer(Handle timerHandle, bool* currentSignaledState = nullptr) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtCancelTimer,
        .arg1 = static_cast<uint64_t>(timerHandle),
        .arg2 = reinterpret_cast<uint64_t>(currentSignaledState)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 33. NtShutdownSystem (SSN: 0x0118)
inline NtStatus NtShutdownSystem(uint32_t action) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtShutdownSystem,
        .arg1 = action
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 34. NtCreateSection (SSN: 0x004A)
inline NtStatus NtCreateSection(
    Handle* sectionHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    LargeInteger* maximumSize,
    uint32_t sectionPageProtection,
    uint32_t allocationAttributes,
    Handle fileHandle
) {
    uint64_t stack[3] = {
        sectionPageProtection,
        allocationAttributes,
        static_cast<uint64_t>(fileHandle)
    };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtCreateSection,
        .arg1 = reinterpret_cast<uint64_t>(sectionHandle),
        .arg2 = desiredAccess,
        .arg3 = reinterpret_cast<uint64_t>(objectAttributes),
        .arg4 = reinterpret_cast<uint64_t>(maximumSize),
        .stackArgs = stack,
        .stackArgCount = 3
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 35. NtMapViewOfSection (SSN: 0x0028)
inline NtStatus NtMapViewOfSection(
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
) {
    uint64_t stack[6] = {
        commitSize,
        reinterpret_cast<uint64_t>(sectionOffset),
        reinterpret_cast<uint64_t>(viewSize),
        inheritDisposition,
        allocationType,
        win32Protect
    };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtMapViewOfSection,
        .arg1 = static_cast<uint64_t>(sectionHandle),
        .arg2 = static_cast<uint64_t>(processHandle),
        .arg3 = reinterpret_cast<uint64_t>(baseAddress),
        .arg4 = zeroBits,
        .stackArgs = stack,
        .stackArgCount = 6
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 36. NtUnmapViewOfSection (SSN: 0x002A)
inline NtStatus NtUnmapViewOfSection(Handle processHandle, uintptr_t baseAddress) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtUnmapViewOfSection,
        .arg1 = static_cast<uint64_t>(processHandle),
        .arg2 = baseAddress
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 37. NtQueryInformationFile (SSN: 0x0011)
inline NtStatus NtQueryInformationFile(
    Handle fileHandle,
    IoStatusBlock* ioStatusBlock,
    void* fileInformation,
    uint32_t length,
    FileInformationClass fileInformationClass
) {
    uint64_t stack[1] = { static_cast<uint64_t>(fileInformationClass) };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtQueryInformationFile,
        .arg1 = static_cast<uint64_t>(fileHandle),
        .arg2 = reinterpret_cast<uint64_t>(ioStatusBlock),
        .arg3 = reinterpret_cast<uint64_t>(fileInformation),
        .arg4 = length,
        .stackArgs = stack,
        .stackArgCount = 1
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 38. NtSetInformationFile (SSN: 0x0027)
inline NtStatus NtSetInformationFile(
    Handle fileHandle,
    IoStatusBlock* ioStatusBlock,
    const void* fileInformation,
    uint32_t length,
    FileInformationClass fileInformationClass
) {
    uint64_t stack[1] = { static_cast<uint64_t>(fileInformationClass) };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtSetInformationFile,
        .arg1 = static_cast<uint64_t>(fileHandle),
        .arg2 = reinterpret_cast<uint64_t>(ioStatusBlock),
        .arg3 = reinterpret_cast<uint64_t>(fileInformation),
        .arg4 = length,
        .stackArgs = stack,
        .stackArgCount = 1
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 39. NtQueryDirectoryFile (SSN: 0x0035)
inline NtStatus NtQueryDirectoryFile(
    Handle fileHandle,
    Handle event,
    void* apcRoutine,
    void* apcContext,
    IoStatusBlock* ioStatusBlock,
    void* fileInformation,
    uint32_t length,
    FileInformationClass fileInformationClass,
    bool returnSingleEntry,
    UnicodeString* fileName = nullptr,
    bool restartScan = false
) {
    uint64_t stack[7] = {
        reinterpret_cast<uint64_t>(ioStatusBlock),
        reinterpret_cast<uint64_t>(fileInformation),
        length,
        static_cast<uint64_t>(fileInformationClass),
        returnSingleEntry ? 1ULL : 0ULL,
        reinterpret_cast<uint64_t>(fileName),
        restartScan ? 1ULL : 0ULL
    };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtQueryDirectoryFile,
        .arg1 = static_cast<uint64_t>(fileHandle),
        .arg2 = static_cast<uint64_t>(event),
        .arg3 = reinterpret_cast<uint64_t>(apcRoutine),
        .arg4 = reinterpret_cast<uint64_t>(apcContext),
        .stackArgs = stack,
        .stackArgCount = 7
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 40. NtQueryPerformanceCounter (SSN: 0x0031)
inline NtStatus NtQueryPerformanceCounter(
    LargeInteger* performanceCounter,
    LargeInteger* performanceFrequency = nullptr
) {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtQueryPerformanceCounter,
        .arg1 = reinterpret_cast<uint64_t>(performanceCounter),
        .arg2 = reinterpret_cast<uint64_t>(performanceFrequency)
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 41. NtYieldExecution (SSN: 0x0046)
inline NtStatus NtYieldExecution() {
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtYieldExecution,
        .arg1 = 0
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 42. NtQueryInformationProcess (SSN: 0x0019)
inline NtStatus NtQueryInformationProcess(
    Handle processHandle,
    ProcessInformationClass processInformationClass,
    void* processInformation,
    uint32_t processInformationLength,
    uint32_t* returnLength = nullptr
) {
    uint64_t stack[1] = { reinterpret_cast<uint64_t>(returnLength) };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtQueryInformationProcess,
        .arg1 = static_cast<uint64_t>(processHandle),
        .arg2 = static_cast<uint64_t>(processInformationClass),
        .arg3 = reinterpret_cast<uint64_t>(processInformation),
        .arg4 = processInformationLength,
        .stackArgs = stack,
        .stackArgCount = 1
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 43. NtCreateNamedPipeFile (SSN: 0x0091)
inline NtStatus NtCreateNamedPipeFile(
    Handle* fileHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    IoStatusBlock* ioStatusBlock,
    uint32_t shareAccess = 0,
    uint32_t createDisposition = 1,
    uint32_t createOptions = 0,
    uint32_t namedPipeType = 0,
    uint32_t readMode = 0,
    uint32_t completionMode = 0,
    uint32_t maximumInstances = 0,
    uint32_t inboundQuota = 0,
    uint32_t outboundQuota = 0,
    LargeInteger* defaultTimeout = nullptr
) {
    uint64_t stack[10] = {
        shareAccess,
        createDisposition,
        createOptions,
        namedPipeType,
        readMode,
        completionMode,
        maximumInstances,
        inboundQuota,
        outboundQuota,
        reinterpret_cast<uint64_t>(defaultTimeout)
    };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtCreateNamedPipeFile,
        .arg1 = reinterpret_cast<uint64_t>(fileHandle),
        .arg2 = desiredAccess,
        .arg3 = reinterpret_cast<uint64_t>(objectAttributes),
        .arg4 = reinterpret_cast<uint64_t>(ioStatusBlock),
        .stackArgs = stack,
        .stackArgCount = 10
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// 44. NtCreateMailslotFile (SSN: 0x0092)
inline NtStatus NtCreateMailslotFile(
    Handle* fileHandle,
    uint32_t desiredAccess,
    ObjectAttributes* objectAttributes,
    IoStatusBlock* ioStatusBlock,
    uint32_t createOptions = 0,
    uint32_t mailslotQuota = 0,
    uint32_t maxMessageSize = 0,
    LargeInteger* readTimeout = nullptr
) {
    uint64_t stack[4] = {
        createOptions,
        mailslotQuota,
        maxMessageSize,
        reinterpret_cast<uint64_t>(readTimeout)
    };
    sys::SyscallFrame frame{
        .ssn = sys::SSN_NtCreateMailslotFile,
        .arg1 = reinterpret_cast<uint64_t>(fileHandle),
        .arg2 = desiredAccess,
        .arg3 = reinterpret_cast<uint64_t>(objectAttributes),
        .arg4 = reinterpret_cast<uint64_t>(ioStatusBlock),
        .stackArgs = stack,
        .stackArgCount = 4
    };
    return sys::SyscallDispatcher::get().dispatch(frame);
}

// ============================================================================
// NTDLL Runtime Library (Rtl) Helpers
// ============================================================================

inline thread_local uint32_t g_FallbackLastError = 0;

inline void RtlSetLastWin32Error(uint32_t errCode) noexcept {
    if (g_CurrentTeb) {
        g_CurrentTeb->lastErrorValue = errCode;
    } else {
        g_FallbackLastError = errCode;
    }
}

inline uint32_t RtlGetLastWin32Error() noexcept {
    if (g_CurrentTeb) {
        return g_CurrentTeb->lastErrorValue;
    }
    return g_FallbackLastError;
}

inline uint32_t RtlNtStatusToDosError(NtStatus status) noexcept {
    if (status == NtStatus::Success) return 0; // ERROR_SUCCESS
    switch (status) {
        case NtStatus::NoSuchFile:              return 2;   // ERROR_FILE_NOT_FOUND
        case NtStatus::ObjectPathNotFound:      return 3;   // ERROR_PATH_NOT_FOUND
        case NtStatus::AccessDenied:            return 5;   // ERROR_ACCESS_DENIED
        case NtStatus::InvalidHandle:           return 6;   // ERROR_INVALID_HANDLE
        case NtStatus::NoMemory:                return 14;  // ERROR_OUTOFMEMORY
        case NtStatus::SharingViolation:        return 32;  // ERROR_SHARING_VIOLATION
        case NtStatus::ObjectNameCollision:     return 80;  // ERROR_FILE_EXISTS
        case NtStatus::InvalidParameter:        return 87;  // ERROR_INVALID_PARAMETER
        case NtStatus::EndOfFile:               return 38;  // ERROR_HANDLE_EOF
        case NtStatus::NotImplemented:          return 120; // ERROR_CALL_NOT_IMPLEMENTED
        case NtStatus::InfoLengthMismatch:      return 24;  // ERROR_BAD_LENGTH
        case NtStatus::NotADirectory:           return 267; // ERROR_DIRECTORY
        case NtStatus::DirectoryNotEmpty:       return 145; // ERROR_DIR_NOT_EMPTY
        case NtStatus::FileIsADirectory:        return 5;   // ERROR_ACCESS_DENIED
        case NtStatus::NoMoreFiles:             return 18;  // ERROR_NO_MORE_FILES
        case NtStatus::BufferOverflow:          return 234; // ERROR_MORE_DATA
        case NtStatus::PipeBroken:              return 109; // ERROR_BROKEN_PIPE
        case NtStatus::PipeBusy:                return 231; // ERROR_PIPE_BUSY
        case NtStatus::PipeClosing:             return 232; // ERROR_NO_DATA
        case NtStatus::PipeDisconnected:        return 233; // ERROR_PIPE_NOT_CONNECTED
        case NtStatus::PipeNotAvailable:        return 233; // ERROR_PIPE_NOT_CONNECTED
        case NtStatus::PipeConnected:           return 535; // ERROR_PIPE_CONNECTED
        case NtStatus::PipeListening:           return 536; // ERROR_PIPE_LISTENING
        case NtStatus::MailslotNotFound:        return 2;   // ERROR_FILE_NOT_FOUND
        case NtStatus::Timeout:                 return 121; // ERROR_SEM_TIMEOUT
        default:                                return NT_SUCCESS(status) ? 0 : 31;  // ERROR_GEN_FAILURE
    }
}

// ============================================================================
// NTDLL Zw* Aliases (Identical Entry Points to Nt* Stubs in Userland)
// ============================================================================
inline NtStatus ZwAllocateVirtualMemory(Handle p, uintptr_t* b, uintptr_t z, size_t* r, uint32_t a, uint32_t pr) {
    return NtAllocateVirtualMemory(p, b, z, r, a, pr);
}
inline NtStatus ZwFreeVirtualMemory(Handle p, uintptr_t* b, size_t* r, uint32_t f) {
    return NtFreeVirtualMemory(p, b, r, f);
}
inline NtStatus ZwClose(Handle h) { return NtClose(h); }
inline NtStatus ZwTerminateProcess(Handle p, NtStatus s) { return NtTerminateProcess(p, s); }
inline NtStatus ZwWaitForSingleObject(Handle h, bool a, LargeInteger* t = nullptr) { return NtWaitForSingleObject(h, a, t); }
inline NtStatus ZwQuerySystemInformation(uint32_t c, void* i, uint32_t l, uint32_t* r) { return NtQuerySystemInformation(c, i, l, r); }
inline NtStatus ZwCreateEvent(Handle* h, uint32_t a, ObjectAttributes* o, uint32_t t, bool s) { return NtCreateEvent(h, a, o, t, s); }
inline NtStatus ZwSetEvent(Handle h, uint32_t* p = nullptr) { return NtSetEvent(h, p); }
inline NtStatus ZwResetEvent(Handle h, uint32_t* p = nullptr) { return NtResetEvent(h, p); }
inline NtStatus ZwCreateMutant(Handle* h, uint32_t a, ObjectAttributes* o, bool i) { return NtCreateMutant(h, a, o, i); }
inline NtStatus ZwReleaseMutant(Handle h, int32_t* p = nullptr) { return NtReleaseMutant(h, p); }
inline NtStatus ZwCreateIoCompletion(Handle* h, uint32_t a, ObjectAttributes* o, uint32_t c) { return NtCreateIoCompletion(h, a, o, c); }
inline NtStatus ZwSetIoCompletion(Handle h, uint64_t k, uintptr_t a, NtStatus s, uint32_t i) { return NtSetIoCompletion(h, k, a, s, i); }
inline NtStatus ZwRemoveIoCompletion(Handle h, uint64_t* k, uintptr_t* a, IoStatusBlock* i, LargeInteger* t = nullptr) { return NtRemoveIoCompletion(h, k, a, i, t); }
inline NtStatus ZwOpenKey(Handle* h, uint32_t a, ObjectAttributes* o) { return NtOpenKey(h, a, o); }
inline NtStatus ZwQueryValueKey(Handle h, UnicodeString* v, uint32_t c, void* i, size_t l, size_t* r) { return NtQueryValueKey(h, v, c, i, l, r); }
inline NtStatus ZwSetValueKey(Handle h, UnicodeString* v, uint32_t t, uint32_t ty, const void* d, uint32_t s) { return NtSetValueKey(h, v, t, ty, d, s); }
inline NtStatus ZwOpenProcessToken(Handle p, uint32_t a, Handle* t) { return NtOpenProcessToken(p, a, t); }
inline NtStatus ZwAccessCheck(void* s, Handle c, uint32_t d, uint32_t* g, NtStatus* a = nullptr) { return NtAccessCheck(s, c, d, g, a); }
inline NtStatus ZwCreatePort(Handle* p, ObjectAttributes* o, uint32_t c = 0, uint32_t m = 256) { return NtCreatePort(p, o, c, m); }
inline NtStatus ZwConnectPort(Handle* p, UnicodeString* n, void* s = nullptr, void* c = nullptr) { return NtConnectPort(p, n, s, c); }
inline NtStatus ZwRequestWaitReplyPort(Handle p, void* rq, void* rp) { return NtRequestWaitReplyPort(p, rq, rp); }
inline NtStatus ZwCreateFile(Handle* f, uint32_t d, ObjectAttributes* o, IoStatusBlock* i, LargeInteger* a = nullptr, uint32_t fa = 0, uint32_t s = 0, uint32_t cd = 1, uint32_t op = 0, void* e = nullptr, uint32_t el = 0) {
    return NtCreateFile(f, d, o, i, a, fa, s, cd, op, e, el);
}
inline NtStatus ZwOpenFile(Handle* f, uint32_t d, ObjectAttributes* o, IoStatusBlock* i, uint32_t s = 0, uint32_t op = 0) {
    return NtOpenFile(f, d, o, i, s, op);
}
inline NtStatus ZwReadFile(Handle f, Handle e, void* a, void* c, IoStatusBlock* i, void* b, uint32_t l, LargeInteger* o = nullptr, uint32_t* k = nullptr) {
    return NtReadFile(f, e, a, c, i, b, l, o, k);
}
inline NtStatus ZwWriteFile(Handle f, Handle e, void* a, void* c, IoStatusBlock* i, const void* b, uint32_t l, LargeInteger* o = nullptr, uint32_t* k = nullptr) {
    return NtWriteFile(f, e, a, c, i, b, l, o, k);
}
inline NtStatus ZwDeviceIoControlFile(Handle f, Handle e, void* a, void* c, IoStatusBlock* i, uint32_t io, const void* in = nullptr, uint32_t inl = 0, void* out = nullptr, uint32_t outl = 0) {
    return NtDeviceIoControlFile(f, e, a, c, i, io, in, inl, out, outl);
}
inline NtStatus ZwWaitForMultipleObjects(uint32_t c, const Handle* h, WaitType w, bool a, LargeInteger* t = nullptr) {
    return NtWaitForMultipleObjects(c, h, w, a, t);
}
inline NtStatus ZwDelayExecution(bool a, const LargeInteger* i) { return NtDelayExecution(a, i); }
inline NtStatus ZwCreateTimer(Handle* h, uint32_t d, ObjectAttributes* o, uint32_t t) { return NtCreateTimer(h, d, o, t); }
inline NtStatus ZwSetTimer(Handle h, LargeInteger* d, void* a = nullptr, void* c = nullptr, bool r = false, uint32_t p = 0, bool* pr = nullptr) {
    return NtSetTimer(h, d, a, c, r, p, pr);
}
inline NtStatus ZwCancelTimer(Handle h, bool* c = nullptr) { return NtCancelTimer(h, c); }
inline NtStatus ZwShutdownSystem(uint32_t a) { return NtShutdownSystem(a); }

inline NtStatus ZwCreateSection(Handle* s, uint32_t a, ObjectAttributes* o, LargeInteger* m, uint32_t p, uint32_t al, Handle f) {
    return NtCreateSection(s, a, o, m, p, al, f);
}
inline NtStatus ZwMapViewOfSection(Handle s, Handle p, uintptr_t* b, uintptr_t z, size_t c, LargeInteger* so, size_t* v, uint32_t i, uint32_t at, uint32_t wp) {
    return NtMapViewOfSection(s, p, b, z, c, so, v, i, at, wp);
}
inline NtStatus ZwUnmapViewOfSection(Handle p, uintptr_t b) { return NtUnmapViewOfSection(p, b); }
inline NtStatus ZwQueryInformationFile(Handle f, IoStatusBlock* i, void* fi, uint32_t l, FileInformationClass c) {
    return NtQueryInformationFile(f, i, fi, l, c);
}
inline NtStatus ZwSetInformationFile(Handle f, IoStatusBlock* i, const void* fi, uint32_t l, FileInformationClass c) {
    return NtSetInformationFile(f, i, fi, l, c);
}
inline NtStatus ZwQueryDirectoryFile(Handle f, Handle e, void* a, void* c, IoStatusBlock* i, void* fi, uint32_t l, FileInformationClass fc, bool s, UnicodeString* fn = nullptr, bool r = false) {
    return NtQueryDirectoryFile(f, e, a, c, i, fi, l, fc, s, fn, r);
}
inline NtStatus ZwQueryPerformanceCounter(LargeInteger* c, LargeInteger* f = nullptr) { return NtQueryPerformanceCounter(c, f); }
inline NtStatus ZwYieldExecution() { return NtYieldExecution(); }
inline NtStatus ZwQueryInformationProcess(Handle p, ProcessInformationClass c, void* i, uint32_t l, uint32_t* r = nullptr) {
    return NtQueryInformationProcess(p, c, i, l, r);
}

} // namespace micant::ntdll

