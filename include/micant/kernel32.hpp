#pragma once

/**
 * @file kernel32.hpp
 * @brief Clean-Room Win32 Base API Bridge (kernel32.dll / kernelbase.dll).
 *
 * Implements the standard Win32 API layer on top of MicaNT clean-room ntdll.dll
 * system call stubs and the CSRSS subsystem server.
 *
 * References: Microsoft win32metadata & Microsoft Learn Public Win32 API Specification.
 */

#include <cstdint>
#include <string_view>
#include <string>
#include <chrono>
#include <thread>
#include <algorithm>
#include <cstdlib>
#include <cwctype>
#include <mutex>
#include <unordered_map>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ntdll.hpp"
#include "ldr.hpp"
#include "csrss.hpp"
#include "conhost.hpp"
#include "hal.hpp"
#include "npfs.hpp"
#include "fs.hpp"

namespace micant::win32 {

inline uintptr_t g_CurrentExecutableBase = 0;

// ============================================================================
// 1. Standard Win32 Types & Constants
// ============================================================================

using DWORD   = uint32_t;
using UINT    = uint32_t;
using BOOL    = int32_t;
using HANDLE  = void*;
using HMODULE = void*;
using HWND    = void*;
using HINSTANCE = void*;
using HICON   = void*;
using HKEY    = void*;
using LPVOID  = void*;
using LPCVOID = const void*;
using LPCWSTR = const wchar_t*;
using LPWSTR  = wchar_t*;
using LPWCH   = wchar_t*;
using LPCSTR  = const char*;
using LPSTR   = char*;
using SIZE_T    = size_t;
using DWORD_PTR = uintptr_t;
using ULONG_PTR = uintptr_t;
using LONG_PTR  = intptr_t;

inline constexpr BOOL TRUE  = 1;
inline constexpr BOOL FALSE = 0;
inline const HANDLE INVALID_HANDLE_VALUE = reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1));

/**
 * @brief Retrieves the calling thread's last-error code value.
 */
inline DWORD GetLastError() noexcept {
    return ntdll::RtlGetLastWin32Error();
}

/**
 * @brief Sets the last-error code for the calling thread.
 */
inline void SetLastError(DWORD dwErrCode) noexcept {
    ntdll::RtlSetLastWin32Error(dwErrCode);
}

// Heap Flags
inline constexpr DWORD HEAP_NO_SERIALIZE        = 0x00000001;
inline constexpr DWORD HEAP_GENERATE_EXCEPTIONS = 0x00000004;
inline constexpr DWORD HEAP_ZERO_MEMORY         = 0x00000008;

// Standard I/O Device Pseudo-Handles
inline constexpr DWORD STD_INPUT_HANDLE  = static_cast<DWORD>(-10);
inline constexpr DWORD STD_OUTPUT_HANDLE = static_cast<DWORD>(-11);
inline constexpr DWORD STD_ERROR_HANDLE  = static_cast<DWORD>(-12);

// File Access & Creation Flags
inline constexpr DWORD GENERIC_READ     = 0x80000000;
inline constexpr DWORD GENERIC_WRITE    = 0x40000000;
inline constexpr DWORD GENERIC_EXECUTE  = 0x20000000;
inline constexpr DWORD GENERIC_ALL      = 0x10000000;

inline constexpr DWORD FILE_SHARE_READ  = 0x00000001;
inline constexpr DWORD FILE_SHARE_WRITE = 0x00000002;

inline constexpr DWORD CREATE_NEW        = 1;
inline constexpr DWORD CREATE_ALWAYS     = 2;
inline constexpr DWORD OPEN_EXISTING     = 3;
inline constexpr DWORD OPEN_ALWAYS       = 4;
inline constexpr DWORD TRUNCATE_EXISTING = 5;

// Memory Allocation Types & Protection
inline constexpr DWORD MEM_COMMIT   = 0x00001000;
inline constexpr DWORD MEM_RESERVE  = 0x00002000;
inline constexpr DWORD MEM_DECOMMIT = 0x00004000;
inline constexpr DWORD MEM_RELEASE  = 0x00008000;

inline constexpr DWORD PAGE_NOACCESS          = 0x01;
inline constexpr DWORD PAGE_READONLY          = 0x02;
inline constexpr DWORD PAGE_READWRITE         = 0x04;
inline constexpr DWORD PAGE_EXECUTE           = 0x10;
inline constexpr DWORD PAGE_EXECUTE_READ      = 0x20;
inline constexpr DWORD PAGE_EXECUTE_READWRITE = 0x40;

// Synchronization Constants
inline constexpr DWORD INFINITE     = 0xFFFFFFFF;
inline constexpr DWORD WAIT_OBJECT_0= 0x00000000;
inline constexpr DWORD WAIT_TIMEOUT = 0x00000102;
inline constexpr DWORD WAIT_FAILED  = 0xFFFFFFFF;

// Move Method Constants for SetFilePointer
inline constexpr DWORD FILE_BEGIN   = 0;
inline constexpr DWORD FILE_CURRENT = 1;
inline constexpr DWORD FILE_END     = 2;

// File Attributes Constants
inline constexpr DWORD FILE_ATTRIBUTE_READONLY  = 0x00000001;
inline constexpr DWORD FILE_ATTRIBUTE_HIDDEN    = 0x00000002;
inline constexpr DWORD FILE_ATTRIBUTE_SYSTEM    = 0x00000004;
inline constexpr DWORD FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
inline constexpr DWORD FILE_ATTRIBUTE_ARCHIVE   = 0x00000020;
inline constexpr DWORD FILE_ATTRIBUTE_NORMAL    = 0x00000080;
inline constexpr DWORD INVALID_FILE_ATTRIBUTES  = static_cast<DWORD>(-1);
inline constexpr DWORD INVALID_FILE_SIZE        = static_cast<DWORD>(-1);

// Console Mode Flags
inline constexpr DWORD ENABLE_PROCESSED_INPUT   = 0x0001;
inline constexpr DWORD ENABLE_LINE_INPUT        = 0x0002;
inline constexpr DWORD ENABLE_ECHO_INPUT        = 0x0004;
inline constexpr DWORD ENABLE_WINDOW_INPUT      = 0x0008;
inline constexpr DWORD ENABLE_MOUSE_INPUT       = 0x0010;
inline constexpr DWORD ENABLE_INSERT_MODE       = 0x0020;
inline constexpr DWORD ENABLE_QUICK_EDIT_MODE   = 0x0040;
inline constexpr DWORD ENABLE_EXTENDED_FLAGS    = 0x0080;
inline constexpr DWORD ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200;

inline constexpr DWORD ENABLE_PROCESSED_OUTPUT  = 0x0001;
inline constexpr DWORD ENABLE_WRAP_AT_EOL_OUTPUT= 0x0002;
inline constexpr DWORD ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;

// Section / File Mapping Access
inline constexpr DWORD FILE_MAP_WRITE           = 0x0002;
inline constexpr DWORD FILE_MAP_READ            = 0x0004;
inline constexpr DWORD FILE_MAP_ALL_ACCESS      = 0x001F001F;
inline constexpr DWORD FILE_MAP_EXECUTE         = 0x0020;

/**
 * @brief Win32 System Information.
 */
struct SYSTEM_INFO {
    uint16_t wProcessorArchitecture{9}; // PROCESSOR_ARCHITECTURE_AMD64
    uint16_t wReserved{0};
    DWORD dwPageSize{4096};
    LPVOID lpMinimumApplicationAddress{reinterpret_cast<LPVOID>(0x10000)};
    LPVOID lpMaximumApplicationAddress{reinterpret_cast<LPVOID>(0x00007FFFFFFEFFFFULL)};
    uintptr_t dwActiveProcessorMask{0x0F}; // 4 cores
    DWORD dwNumberOfProcessors{4};
    DWORD dwProcessorType{8664};
    DWORD dwAllocationGranularity{65536};
    uint16_t wProcessorLevel{6};
    uint16_t wProcessorRevision{0};
};

struct WIN32_FIND_DATAW {
    DWORD dwFileAttributes{0};
    uint32_t ftCreationTimeLow{0};
    uint32_t ftCreationTimeHigh{0};
    uint32_t ftLastAccessTimeLow{0};
    uint32_t ftLastAccessTimeHigh{0};
    uint32_t ftLastWriteTimeLow{0};
    uint32_t ftLastWriteTimeHigh{0};
    DWORD nFileSizeHigh{0};
    DWORD nFileSizeLow{0};
    DWORD dwReserved0{0};
    DWORD dwReserved1{0};
    wchar_t cFileName[260]{};
    wchar_t cAlternateFileName[14]{};
};

struct SYSTEMTIME {
    uint16_t wYear{2026};
    uint16_t wMonth{10};
    uint16_t wDayOfWeek{4}; // Thursday
    uint16_t wDay{1};
    uint16_t wHour{9};
    uint16_t wMinute{0};
    uint16_t wSecond{0};
    uint16_t wMilliseconds{0};
};


// ============================================================================
// 2. Memory Management (Heap & Virtual Memory)
// ============================================================================

/**
 * @brief Retrieves a handle to the default heap of the calling process.
 */
inline HANDLE GetProcessHeap() noexcept {
    auto* peb = ntdll::RtlGetCurrentPeb();
    if (peb && peb->processHeap != 0) {
        return reinterpret_cast<HANDLE>(peb->processHeap);
    }

    static HANDLE s_defaultProcessHeap = nullptr;
    if (!s_defaultProcessHeap) {
        s_defaultProcessHeap = ntdll::RtlCreateHeap(heap::HEAP_GROWABLE, nullptr, 0, 0x100000, nullptr, nullptr);
    }
    if (peb && peb->processHeap == 0) {
        peb->processHeap = reinterpret_cast<uint64_t>(s_defaultProcessHeap);
    }
    return s_defaultProcessHeap;
}

/**
 * @brief Allocates a block of memory from a heap.
 */
inline LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) noexcept {
    return ntdll::RtlAllocateHeap(hHeap, dwFlags, dwBytes);
}

/**
 * @brief Frees a memory block allocated from a heap.
 */
inline BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) noexcept {
    return ntdll::RtlFreeHeap(hHeap, dwFlags, lpMem) ? TRUE : FALSE;
}

/**
 * @brief Reallocates a block of memory from a heap.
 */
inline LPVOID HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) noexcept {
    return ntdll::RtlReAllocateHeap(hHeap, dwFlags, lpMem, dwBytes);
}

/**
 * @brief Retrieves the size of a memory block allocated from a heap.
 */
inline SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem) noexcept {
    return ntdll::RtlSizeHeap(hHeap, dwFlags, const_cast<LPVOID>(lpMem));
}

using HLOCAL = void*;
inline constexpr UINT LMEM_FIXED    = 0x0000;
inline constexpr UINT LMEM_MOVEABLE = 0x0002;
inline constexpr UINT LMEM_ZEROINIT = 0x0040;
inline constexpr UINT LPTR          = 0x0040;

inline HLOCAL LocalAlloc(UINT uFlags, SIZE_T uBytes) noexcept {
    DWORD flags = (uFlags & LMEM_ZEROINIT) ? heap::HEAP_ZERO_MEMORY : 0;
    return reinterpret_cast<HLOCAL>(HeapAlloc(GetProcessHeap(), flags, uBytes));
}

inline HLOCAL LocalFree(HLOCAL hMem) noexcept {
    if (hMem) {
        HeapFree(GetProcessHeap(), 0, reinterpret_cast<LPVOID>(hMem));
    }
    return nullptr;
}

/**
 * @brief Reserves, commits, or changes the state of a region of pages in virtual memory.
 */
inline LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) noexcept {
    uintptr_t base = reinterpret_cast<uintptr_t>(lpAddress);
    SIZE_T size = dwSize;
    NtStatus status = ntdll::NtAllocateVirtualMemory(
        static_cast<Handle>(-1), // CurrentProcess
        &base,
        0,
        &size,
        flAllocationType,
        flProtect
    );
    if (!NT_SUCCESS(status)) return nullptr;
    return reinterpret_cast<LPVOID>(base);
}

/**
 * @brief Releases, decommits, or releases and decommits a region of pages in virtual memory.
 */
inline BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) noexcept {
    uintptr_t base = reinterpret_cast<uintptr_t>(lpAddress);
    SIZE_T size = dwSize;
    NtStatus status = ntdll::NtFreeVirtualMemory(
        static_cast<Handle>(-1),
        &base,
        &size,
        dwFreeType
    );
    return NT_SUCCESS(status) ? TRUE : FALSE;
}

// ============================================================================
// 3. Process & Thread Management
// ============================================================================

/**
 * @brief Retrieves a pseudo handle for the current process.
 */
inline HANDLE GetCurrentProcess() noexcept {
    return reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1));
}

/**
 * @brief Retrieves the process identifier of the calling process.
 */
inline DWORD GetCurrentProcessId() noexcept {
    auto* teb = ntdll::RtlGetCurrentTeb();
    if (!teb || teb->clientId.uniqueProcess == 0) return 1000;
    return static_cast<DWORD>(teb->clientId.uniqueProcess);
}

/**
 * @brief Retrieves a pseudo handle for the current thread.
 */
inline HANDLE GetCurrentThread() noexcept {
    return reinterpret_cast<HANDLE>(static_cast<intptr_t>(-2));
}

/**
 * @brief Retrieves the thread identifier of the calling thread.
 */
inline DWORD GetCurrentThreadId() noexcept {
    auto* teb = ntdll::RtlGetCurrentTeb();
    if (!teb || teb->clientId.uniqueThread == 0) return 1;
    return static_cast<DWORD>(teb->clientId.uniqueThread);
}

/**
 * @brief Ends the calling process and all its threads.
 */
[[noreturn]] inline void ExitProcess(DWORD uExitCode) noexcept {
    DWORD pid = GetCurrentProcessId();
    // Notify CSRSS subsystem
    csrss::CsrSubsystemServer::get().terminateProcess(pid, uExitCode);
    conhost::ConhostManager::get().freeConsole(pid);
    ntdll::NtTerminateProcess(static_cast<Handle>(-1), static_cast<NtStatus>(uExitCode));
    std::exit(static_cast<int>(uExitCode));
}

// ============================================================================
// 4. Console Management (conhost / csrss integration)
// ============================================================================

/**
 * @brief Retrieves a handle to the specified standard device (input, output, or error).
 */
inline HANDLE GetStdHandle(DWORD nStdHandle) noexcept {
    auto* peb = ntdll::RtlGetCurrentPeb();
    if (!peb || peb->processParameters == 0) {
        if (nStdHandle == STD_INPUT_HANDLE) return reinterpret_cast<HANDLE>(0x10);
        if (nStdHandle == STD_OUTPUT_HANDLE) return reinterpret_cast<HANDLE>(0x14);
        if (nStdHandle == STD_ERROR_HANDLE) return reinterpret_cast<HANDLE>(0x18);
        return INVALID_HANDLE_VALUE;
    }

    auto* params = reinterpret_cast<ldr::RtlUserProcessParameters*>(peb->processParameters);
    if (nStdHandle == STD_INPUT_HANDLE) {
        return reinterpret_cast<HANDLE>(params->standardInput);
    }
    if (nStdHandle == STD_OUTPUT_HANDLE) {
        return reinterpret_cast<HANDLE>(params->standardOutput);
    }
    if (nStdHandle == STD_ERROR_HANDLE) {
        return reinterpret_cast<HANDLE>(params->standardError);
    }
    return INVALID_HANDLE_VALUE;
}

/**
 * @brief Sets the handle for the specified standard device.
 */
inline BOOL SetStdHandle(DWORD nStdHandle, HANDLE hHandle) noexcept {
    auto* peb = ntdll::RtlGetCurrentPeb();
    if (!peb || peb->processParameters == 0) return FALSE;

    auto* params = reinterpret_cast<ldr::RtlUserProcessParameters*>(peb->processParameters);
    Handle h = reinterpret_cast<Handle>(hHandle);
    if (nStdHandle == STD_INPUT_HANDLE) params->standardInput = h;
    else if (nStdHandle == STD_OUTPUT_HANDLE) params->standardOutput = h;
    else if (nStdHandle == STD_ERROR_HANDLE) params->standardError = h;
    else return FALSE;

    return TRUE;
}

/**
 * @brief Allocates a new console for the calling process.
 */
inline BOOL AllocConsole() noexcept {
    DWORD pid = GetCurrentProcessId();
    auto session = conhost::ConhostManager::get().allocateConsole(pid, L"MicaNT Console");
    if (!session) return FALSE;

    SetStdHandle(STD_INPUT_HANDLE, reinterpret_cast<HANDLE>(session->getInputHandle()));
    SetStdHandle(STD_OUTPUT_HANDLE, reinterpret_cast<HANDLE>(session->getOutputHandle()));
    SetStdHandle(STD_ERROR_HANDLE, reinterpret_cast<HANDLE>(session->getErrorHandle()));

    csrss::CsrSubsystemServer::get().bindConsole(pid, session->getOutputHandle());
    return TRUE;
}

/**
 * @brief Detaches the calling process from its console.
 */
inline BOOL FreeConsole() noexcept {
    DWORD pid = GetCurrentProcessId();
    csrss::CsrSubsystemServer::get().unbindConsole(pid);
    return conhost::ConhostManager::get().freeConsole(pid) ? TRUE : FALSE;
}

/**
 * @brief Sets the title for the current console window.
 */
inline BOOL SetConsoleTitleW(LPCWSTR lpConsoleTitle) noexcept {
    if (!lpConsoleTitle) return FALSE;
    DWORD pid = GetCurrentProcessId();
    auto session = conhost::ConhostManager::get().getConsole(pid);
    if (!session) return FALSE;
    session->setTitle(lpConsoleTitle);
    return TRUE;
}

/**
 * @brief Retrieves the title for the current console window.
 */
inline DWORD GetConsoleTitleW(LPWSTR lpConsoleTitle, DWORD nSize) noexcept {
    if (!lpConsoleTitle || nSize == 0) return 0;
    DWORD pid = GetCurrentProcessId();
    auto session = conhost::ConhostManager::get().getConsole(pid);
    if (!session) return 0;

    const std::wstring& title = session->getTitle();
    DWORD copyLen = std::min<DWORD>(nSize - 1, static_cast<DWORD>(title.length()));
    for (DWORD i = 0; i < copyLen; ++i) {
        lpConsoleTitle[i] = title[i];
    }
    lpConsoleTitle[copyLen] = L'\0';
    return copyLen;
}

/**
 * @brief Writes a character string to a console screen buffer beginning at current cursor.
 */
inline BOOL WriteConsoleW(
    HANDLE hConsoleOutput,
    const void* lpBuffer,
    DWORD nNumberOfCharsToWrite,
    DWORD* lpNumberOfCharsWritten,
    void* lpReserved = nullptr
) noexcept {
    (void)lpReserved;
    if (!lpBuffer || nNumberOfCharsToWrite == 0) return FALSE;

    DWORD pid = GetCurrentProcessId();
    auto session = conhost::ConhostManager::get().getConsole(pid);
    if (session) {
        std::wstring_view sv(reinterpret_cast<const wchar_t*>(lpBuffer), nNumberOfCharsToWrite);
        session->writeOutput(sv);
        if (lpNumberOfCharsWritten) *lpNumberOfCharsWritten = nNumberOfCharsToWrite;
        return TRUE;
    }

    // Direct NT write fallback for standard console handle
    IoStatusBlock iosb{};
    NtStatus status = ntdll::NtWriteFile(
        reinterpret_cast<Handle>(hConsoleOutput),
        0, nullptr, nullptr,
        &iosb,
        const_cast<void*>(lpBuffer),
        nNumberOfCharsToWrite * sizeof(wchar_t),
        nullptr, nullptr
    );

    if (lpNumberOfCharsWritten) {
        *lpNumberOfCharsWritten = static_cast<DWORD>(iosb.information / sizeof(wchar_t));
    }
    return NT_SUCCESS(status) ? TRUE : FALSE;
}

// ============================================================================
// 5. File I/O
// ============================================================================

/**
 * @brief Creates or opens a file or I/O device.
 */
inline HANDLE CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    void* lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile = nullptr
) noexcept {
    (void)dwShareMode;
    (void)lpSecurityAttributes;
    (void)dwFlagsAndAttributes;
    (void)hTemplateFile;

    if (!lpFileName) return INVALID_HANDLE_VALUE;

    UnicodeString uniPath(lpFileName);
    ObjectAttributes objAttr{};
    objAttr.objectName = &uniPath;

    Handle hFile = 0;
    IoStatusBlock iosb{};

    uint32_t createDisposition = 1; // FILE_OPEN
    if (dwCreationDisposition == CREATE_ALWAYS || dwCreationDisposition == CREATE_NEW) {
        createDisposition = 2; // FILE_CREATE
    } else if (dwCreationDisposition == OPEN_ALWAYS) {
        createDisposition = 3; // FILE_OPEN_IF
    }

    NtStatus status = ntdll::NtCreateFile(
        &hFile,
        dwDesiredAccess,
        &objAttr,
        &iosb,
        nullptr,
        0,
        dwShareMode,
        createDisposition,
        0,
        nullptr,
        0
    );

    if (!NT_SUCCESS(status)) return INVALID_HANDLE_VALUE;
    return reinterpret_cast<HANDLE>(hFile);
}

/**
 * @brief Reads data from the specified file or input device.
 */
inline BOOL ReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    DWORD* lpNumberOfBytesRead,
    void* lpOverlapped = nullptr
) noexcept {
    (void)lpOverlapped;
    if (!lpBuffer) return FALSE;

    IoStatusBlock iosb{};
    NtStatus status = ntdll::NtReadFile(
        reinterpret_cast<Handle>(hFile),
        0, nullptr, nullptr,
        &iosb,
        lpBuffer,
        nNumberOfBytesToRead,
        nullptr, nullptr
    );

    if (lpNumberOfBytesRead) {
        *lpNumberOfBytesRead = static_cast<DWORD>(iosb.information);
    }
    if (!NT_SUCCESS(status) || status == NtStatus::Timeout) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief Writes data to the specified file or output device.
 */
inline BOOL WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    DWORD* lpNumberOfBytesWritten,
    void* lpOverlapped = nullptr
) noexcept {
    (void)lpOverlapped;
    if (!lpBuffer) return FALSE;

    IoStatusBlock iosb{};
    NtStatus status = ntdll::NtWriteFile(
        reinterpret_cast<Handle>(hFile),
        0, nullptr, nullptr,
        &iosb,
        const_cast<void*>(lpBuffer),
        nNumberOfBytesToWrite,
        nullptr, nullptr
    );

    if (lpNumberOfBytesWritten) {
        *lpNumberOfBytesWritten = static_cast<DWORD>(iosb.information);
    }
    if (!NT_SUCCESS(status) || status == NtStatus::Timeout) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief Closes an open object handle.
 */
inline BOOL CloseHandle(HANDLE hObject) noexcept {
    if (hObject == nullptr || hObject == INVALID_HANDLE_VALUE) return FALSE;
    NtStatus status = ntdll::NtClose(reinterpret_cast<Handle>(hObject));
    return NT_SUCCESS(status) ? TRUE : FALSE;
}

// ============================================================================
// 5.1 Named Pipes & Mailslots Inter-Process Communication (IPC)
// ============================================================================

inline constexpr DWORD PIPE_ACCESS_INBOUND         = 0x00000001;
inline constexpr DWORD PIPE_ACCESS_OUTBOUND        = 0x00000002;
inline constexpr DWORD PIPE_ACCESS_DUPLEX          = 0x00000003;

inline constexpr DWORD PIPE_WAIT                   = 0x00000000;
inline constexpr DWORD PIPE_NOWAIT                 = 0x00000001;
inline constexpr DWORD PIPE_READMODE_BYTE          = 0x00000000;
inline constexpr DWORD PIPE_READMODE_MESSAGE       = 0x00000002;
inline constexpr DWORD PIPE_TYPE_BYTE              = 0x00000000;
inline constexpr DWORD PIPE_TYPE_MESSAGE           = 0x00000004;

inline constexpr DWORD PIPE_CLIENT_END             = 0x00000000;
inline constexpr DWORD PIPE_SERVER_END             = 0x00000001;
inline constexpr DWORD PIPE_UNLIMITED_INSTANCES    = 255;

inline constexpr DWORD NMPWAIT_WAIT_FOREVER        = 0xFFFFFFFF;
inline constexpr DWORD NMPWAIT_NOWAIT              = 0x00000001;
inline constexpr DWORD NMPWAIT_USE_DEFAULT_WAIT    = 0x00000000;

inline constexpr DWORD MAILSLOT_NO_MESSAGE         = static_cast<DWORD>(-1);
inline constexpr DWORD MAILSLOT_WAIT_FOREVER       = static_cast<DWORD>(-1);

inline constexpr DWORD ERROR_PIPE_BUSY             = 231;
inline constexpr DWORD ERROR_NO_DATA               = 232;
inline constexpr DWORD ERROR_PIPE_NOT_CONNECTED    = 233;
inline constexpr DWORD ERROR_MORE_DATA             = 234;
inline constexpr DWORD ERROR_PIPE_CONNECTED        = 535;
inline constexpr DWORD ERROR_PIPE_LISTENING        = 536;
inline constexpr DWORD ERROR_BROKEN_PIPE           = 109;

inline HANDLE CreateNamedPipeW(
    LPCWSTR lpName,
    DWORD dwOpenMode,
    DWORD dwPipeMode,
    DWORD nMaxInstances,
    DWORD nOutBufferSize,
    DWORD nInBufferSize,
    DWORD nDefaultTimeOut,
    void* lpSecurityAttributes = nullptr
) noexcept {
    (void)lpSecurityAttributes;
    if (!lpName) {
        SetLastError(87); // ERROR_INVALID_PARAMETER
        return INVALID_HANDLE_VALUE;
    }

    UnicodeString uniName(lpName);
    ObjectAttributes objAttr{};
    objAttr.objectName = &uniName;

    Handle hPipe = 0;
    IoStatusBlock iosb{};

    uint32_t type = (dwPipeMode & PIPE_TYPE_MESSAGE) ? 1 : 0;
    uint32_t readMode = (dwPipeMode & PIPE_READMODE_MESSAGE) ? 1 : 0;
    uint32_t nonBlocking = (dwPipeMode & PIPE_NOWAIT) ? 1 : 0;

    LargeInteger timeout{};
    timeout.quadPart = -static_cast<int64_t>(nDefaultTimeOut) * 10000;

    NtStatus status = ntdll::NtCreateNamedPipeFile(
        &hPipe,
        dwOpenMode,
        &objAttr,
        &iosb,
        0,
        2,
        0,
        type,
        readMode,
        nonBlocking,
        nMaxInstances,
        nInBufferSize,
        nOutBufferSize,
        &timeout
    );

    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return INVALID_HANDLE_VALUE;
    }

    return reinterpret_cast<HANDLE>(hPipe);
}

inline BOOL ConnectNamedPipe(
    HANDLE hNamedPipe,
    void* lpOverlapped = nullptr
) noexcept {
    (void)lpOverlapped;
    if (hNamedPipe == nullptr || hNamedPipe == INVALID_HANDLE_VALUE) {
        SetLastError(6); // ERROR_INVALID_HANDLE
        return FALSE;
    }

    fs::FileObject* fileObj = sys::LookupKernelFileObject(reinterpret_cast<Handle>(hNamedPipe));
    if (!fileObj || !fileObj->getFsContext()) {
        SetLastError(6); // ERROR_INVALID_HANDLE
        return FALSE;
    }

    auto* pipeInst = static_cast<npfs::NamedPipeInstance*>(fileObj->getFsContext());
    NtStatus status = pipeInst->connectServer(npfs::NMPWAIT_WAIT_FOREVER);
    if (status == NtStatus::PipeConnected) {
        SetLastError(ERROR_PIPE_CONNECTED);
        return FALSE;
    }

    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }

    return TRUE;
}

inline BOOL DisconnectNamedPipe(
    HANDLE hNamedPipe
) noexcept {
    if (hNamedPipe == nullptr || hNamedPipe == INVALID_HANDLE_VALUE) {
        SetLastError(6); // ERROR_INVALID_HANDLE
        return FALSE;
    }

    fs::FileObject* fileObj = sys::LookupKernelFileObject(reinterpret_cast<Handle>(hNamedPipe));
    if (!fileObj || !fileObj->getFsContext()) {
        SetLastError(6); // ERROR_INVALID_HANDLE
        return FALSE;
    }

    auto* pipeInst = static_cast<npfs::NamedPipeInstance*>(fileObj->getFsContext());
    NtStatus status = pipeInst->disconnectServer();
    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }

    return TRUE;
}

inline BOOL WaitNamedPipeW(
    LPCWSTR lpNamedPipeName,
    DWORD nTimeOut
) noexcept {
    if (!lpNamedPipeName) {
        SetLastError(87);
        return FALSE;
    }

    NtStatus status = npfs::NamedPipeFileSystem::get().waitNamedPipe(lpNamedPipeName, nTimeOut);
    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }
    return TRUE;
}

inline BOOL PeekNamedPipe(
    HANDLE hNamedPipe,
    LPVOID lpBuffer,
    DWORD nBufferSize,
    DWORD* lpBytesRead,
    DWORD* lpTotalBytesAvail,
    DWORD* lpBytesLeftThisMessage
) noexcept {
    if (hNamedPipe == nullptr || hNamedPipe == INVALID_HANDLE_VALUE) {
        SetLastError(6); // ERROR_INVALID_HANDLE
        return FALSE;
    }

    fs::FileObject* fileObj = sys::LookupKernelFileObject(reinterpret_cast<Handle>(hNamedPipe));
    if (!fileObj || !fileObj->getFsContext()) {
        SetLastError(6);
        return FALSE;
    }

    auto* pipeInst = static_cast<npfs::NamedPipeInstance*>(fileObj->getFsContext());
    bool isServer = (reinterpret_cast<uintptr_t>(fileObj->getFsContext2()) == 1);

    uint32_t bytesRead = 0;
    uint32_t totalAvail = 0;
    uint32_t leftMsg = 0;

    NtStatus status = pipeInst->peek(
        isServer, lpBuffer, nBufferSize,
        &bytesRead, &totalAvail, &leftMsg
    );

    if (lpBytesRead) *lpBytesRead = bytesRead;
    if (lpTotalBytesAvail) *lpTotalBytesAvail = totalAvail;
    if (lpBytesLeftThisMessage) *lpBytesLeftThisMessage = leftMsg;

    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }
    return TRUE;
}

inline BOOL TransactNamedPipe(
    HANDLE hNamedPipe,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    DWORD* lpBytesRead,
    void* lpOverlapped = nullptr
) noexcept {
    (void)lpOverlapped;
    if (hNamedPipe == nullptr || hNamedPipe == INVALID_HANDLE_VALUE || !lpInBuffer || !lpOutBuffer) {
        SetLastError(87);
        return FALSE;
    }

    fs::FileObject* fileObj = sys::LookupKernelFileObject(reinterpret_cast<Handle>(hNamedPipe));
    if (!fileObj || !fileObj->getFsContext()) {
        SetLastError(6);
        return FALSE;
    }

    auto* pipeInst = static_cast<npfs::NamedPipeInstance*>(fileObj->getFsContext());
    bool isServer = (reinterpret_cast<uintptr_t>(fileObj->getFsContext2()) == 1);

    uint32_t bytesRead = 0;
    NtStatus status = pipeInst->transact(
        isServer, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, bytesRead
    );

    if (lpBytesRead) *lpBytesRead = bytesRead;

    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }
    return TRUE;
}

inline BOOL GetNamedPipeInfo(
    HANDLE hNamedPipe,
    DWORD* lpFlags,
    DWORD* lpOutBufferSize,
    DWORD* lpInBufferSize,
    DWORD* lpMaxInstances
) noexcept {
    if (hNamedPipe == nullptr || hNamedPipe == INVALID_HANDLE_VALUE) {
        SetLastError(6);
        return FALSE;
    }

    fs::FileObject* fileObj = sys::LookupKernelFileObject(reinterpret_cast<Handle>(hNamedPipe));
    if (!fileObj || !fileObj->getFsContext()) {
        SetLastError(6);
        return FALSE;
    }

    auto* pipeInst = static_cast<npfs::NamedPipeInstance*>(fileObj->getFsContext());
    bool isServer = (reinterpret_cast<uintptr_t>(fileObj->getFsContext2()) == 1);

    if (lpFlags) {
        *lpFlags = (isServer ? PIPE_SERVER_END : PIPE_CLIENT_END) |
                   (pipeInst->getPipeMode() & PIPE_TYPE_MESSAGE);
    }
    if (lpOutBufferSize) *lpOutBufferSize = pipeInst->getOutBufferSize();
    if (lpInBufferSize) *lpInBufferSize = pipeInst->getInBufferSize();
    if (lpMaxInstances) *lpMaxInstances = pipeInst->getMaxInstances();

    return TRUE;
}

inline BOOL GetNamedPipeHandleStateW(
    HANDLE hNamedPipe,
    DWORD* lpState,
    DWORD* lpCurInstances,
    DWORD* lpMaxCollectionCount,
    DWORD* lpCollectDataTimeout,
    LPWSTR lpUserName,
    DWORD nMaxUserNameSize
) noexcept {
    (void)lpMaxCollectionCount;
    (void)lpCollectDataTimeout;
    (void)lpUserName;
    (void)nMaxUserNameSize;
    if (hNamedPipe == nullptr || hNamedPipe == INVALID_HANDLE_VALUE) {
        SetLastError(6);
        return FALSE;
    }

    fs::FileObject* fileObj = sys::LookupKernelFileObject(reinterpret_cast<Handle>(hNamedPipe));
    if (!fileObj || !fileObj->getFsContext()) {
        SetLastError(6);
        return FALSE;
    }

    auto* pipeInst = static_cast<npfs::NamedPipeInstance*>(fileObj->getFsContext());
    if (lpState) *lpState = pipeInst->getPipeMode();
    if (lpCurInstances) *lpCurInstances = 1;

    return TRUE;
}

inline BOOL SetNamedPipeHandleState(
    HANDLE hNamedPipe,
    DWORD* lpMode,
    DWORD* lpMaxCollectionCount,
    DWORD* lpCollectDataTimeout
) noexcept {
    (void)lpMaxCollectionCount;
    (void)lpCollectDataTimeout;
    if (hNamedPipe == nullptr || hNamedPipe == INVALID_HANDLE_VALUE) {
        SetLastError(6);
        return FALSE;
    }

    fs::FileObject* fileObj = sys::LookupKernelFileObject(reinterpret_cast<Handle>(hNamedPipe));
    if (!fileObj || !fileObj->getFsContext()) {
        SetLastError(6);
        return FALSE;
    }

    if (lpMode) {
        auto* pipeInst = static_cast<npfs::NamedPipeInstance*>(fileObj->getFsContext());
        pipeInst->setMode(*lpMode);
    }

    return TRUE;
}

inline HANDLE CreateMailslotW(
    LPCWSTR lpName,
    DWORD nMaxMessageSize,
    DWORD lReadTimeout,
    void* lpSecurityAttributes = nullptr
) noexcept {
    (void)lpSecurityAttributes;
    if (!lpName) {
        SetLastError(87);
        return INVALID_HANDLE_VALUE;
    }

    UnicodeString uniName(lpName);
    ObjectAttributes objAttr{};
    objAttr.objectName = &uniName;

    Handle hSlot = 0;
    IoStatusBlock iosb{};

    LargeInteger timeout{};
    timeout.quadPart = (lReadTimeout == MAILSLOT_WAIT_FOREVER) ? -1 : -static_cast<int64_t>(lReadTimeout) * 10000;

    NtStatus status = ntdll::NtCreateMailslotFile(
        &hSlot,
        GENERIC_READ | FILE_SHARE_READ,
        &objAttr,
        &iosb,
        0,
        0,
        nMaxMessageSize,
        &timeout
    );

    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return INVALID_HANDLE_VALUE;
    }

    return reinterpret_cast<HANDLE>(hSlot);
}

inline BOOL GetMailslotInfo(
    HANDLE hMailslot,
    DWORD* lpMaxMessageSize,
    DWORD* lpNextSize,
    DWORD* lpMessageCount,
    DWORD* lpReadTimeout
) noexcept {
    if (hMailslot == nullptr || hMailslot == INVALID_HANDLE_VALUE) {
        SetLastError(6);
        return FALSE;
    }

    fs::FileObject* fileObj = sys::LookupKernelFileObject(reinterpret_cast<Handle>(hMailslot));
    if (!fileObj || !fileObj->getFsContext()) {
        SetLastError(6);
        return FALSE;
    }

    auto* slot = static_cast<npfs::Mailslot*>(fileObj->getFsContext());
    slot->getInfo(lpMaxMessageSize, lpNextSize, lpMessageCount, lpReadTimeout);
    return TRUE;
}

inline BOOL SetMailslotInfo(
    HANDLE hMailslot,
    DWORD lReadTimeout
) noexcept {
    if (hMailslot == nullptr || hMailslot == INVALID_HANDLE_VALUE) {
        SetLastError(6);
        return FALSE;
    }

    fs::FileObject* fileObj = sys::LookupKernelFileObject(reinterpret_cast<Handle>(hMailslot));
    if (!fileObj || !fileObj->getFsContext()) {
        SetLastError(6);
        return FALSE;
    }

    auto* slot = static_cast<npfs::Mailslot*>(fileObj->getFsContext());
    slot->setReadTimeout(lReadTimeout);
    return TRUE;
}

/**
 * @brief Creates or opens a named or unnamed event object.
 */
inline HANDLE CreateEventW(
    void* lpEventAttributes,
    BOOL bManualReset,
    BOOL bInitialState,
    LPCWSTR lpName
) noexcept {
    (void)lpEventAttributes;
    Handle hEvent = 0;
    UnicodeString uniName(lpName);
    ObjectAttributes objAttr{};
    if (lpName) objAttr.objectName = &uniName;

    NtStatus status = ntdll::NtCreateEvent(
        &hEvent,
        0x1F0003, // EVENT_ALL_ACCESS
        &objAttr,
        bManualReset ? 0 : 1, // NotificationEvent = 0, SynchronizationEvent = 1
        bInitialState ? true : false
    );

    if (!NT_SUCCESS(status)) return nullptr;
    return reinterpret_cast<HANDLE>(hEvent);
}

/**
 * @brief Sets the specified event object to the signaled state.
 */
inline BOOL SetEvent(HANDLE hEvent) noexcept {
    if (!hEvent) return FALSE;
    NtStatus status = ntdll::NtSetEvent(reinterpret_cast<Handle>(hEvent), nullptr);
    return NT_SUCCESS(status) ? TRUE : FALSE;
}

/**
 * @brief Sets the specified event object to the nonsignaled state.
 */
inline BOOL ResetEvent(HANDLE hEvent) noexcept {
    if (!hEvent) return FALSE;
    NtStatus status = ntdll::NtResetEvent(reinterpret_cast<Handle>(hEvent), nullptr);
    return NT_SUCCESS(status) ? TRUE : FALSE;
}

/**
 * @brief Waits until the specified object is in the signaled state or the time-out interval elapses.
 */
inline DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) noexcept {
    if (!hHandle) return WAIT_FAILED;

    LargeInteger timeout{};
    LargeInteger* pTimeout = nullptr;
    if (dwMilliseconds != INFINITE) {
        timeout.quadPart = -static_cast<int64_t>(dwMilliseconds) * 10000; // 100ns units
        pTimeout = &timeout;
    }

    NtStatus status = ntdll::NtWaitForSingleObject(
        reinterpret_cast<Handle>(hHandle),
        false,
        pTimeout
    );

    if (status == NtStatus::Success) return WAIT_OBJECT_0;
    if (status == NtStatus::Timeout) return WAIT_TIMEOUT;
    return WAIT_FAILED;
}

/**
 * @brief Waits until one or all of the specified objects are in the signaled state.
 */
inline DWORD WaitForMultipleObjects(
    DWORD nCount,
    const HANDLE* lpHandles,
    BOOL bWaitAll,
    DWORD dwMilliseconds
) noexcept {
    if (nCount == 0 || !lpHandles || nCount > MAXIMUM_WAIT_OBJECTS) return WAIT_FAILED;

    Handle handles[MAXIMUM_WAIT_OBJECTS];
    for (DWORD i = 0; i < nCount; ++i) {
        handles[i] = reinterpret_cast<Handle>(lpHandles[i]);
    }

    LargeInteger timeout{};
    LargeInteger* pTimeout = nullptr;
    if (dwMilliseconds != INFINITE) {
        timeout.quadPart = -static_cast<int64_t>(dwMilliseconds) * 10000;
        pTimeout = &timeout;
    }

    NtStatus status = ntdll::NtWaitForMultipleObjects(
        nCount,
        handles,
        bWaitAll ? WaitType::WaitAll : WaitType::WaitAny,
        false,
        pTimeout
    );

    if (status == NtStatus::Success) return WAIT_OBJECT_0;
    if (static_cast<uint32_t>(status) >= static_cast<uint32_t>(NtStatus::Wait0) &&
        static_cast<uint32_t>(status) < static_cast<uint32_t>(NtStatus::Wait0) + nCount) {
        return static_cast<DWORD>(status);
    }
    if (status == NtStatus::Timeout) return WAIT_TIMEOUT;
    return WAIT_FAILED;
}

// ============================================================================
// 7. Time & System Information
// ============================================================================

/**
 * @brief Suspends the execution of the current thread until the time-out interval elapses.
 */
inline void Sleep(DWORD dwMilliseconds) noexcept {
    LargeInteger interval{};
    interval.quadPart = -static_cast<int64_t>(dwMilliseconds) * 10000; // 100ns
    ntdll::NtDelayExecution(false, &interval);
}

/**
 * @brief Retrieves the number of milliseconds that have elapsed since the system was started.
 */
inline uint64_t GetTickCount64() noexcept {
    LargeInteger perf{};
    hal::HardwareAbstractionLayer::get().queryPerformanceCounter(perf);
    return static_cast<uint64_t>(perf.quadPart / 1000000ULL);
}

/**
 * @brief Retrieves information about the current system.
 */
inline void GetSystemInfo(SYSTEM_INFO* lpSystemInfo) noexcept {
    if (!lpSystemInfo) return;
    *lpSystemInfo = SYSTEM_INFO{};
}

// ============================================================================
// 8. Dynamic Linking & Module Loading
// ============================================================================

/**
 * @brief Loads the specified module into the address space of the calling process.
 */
inline HMODULE LoadLibraryW(LPCWSTR lpLibFileName) noexcept {
    if (!lpLibFileName) return nullptr;
    uintptr_t modBase = 0;
    UnicodeString uniPath(lpLibFileName);
    NtStatus status = ntdll::LdrLoadDll(nullptr, 0, &uniPath, &modBase);
    if (!NT_SUCCESS(status)) return nullptr;
    return reinterpret_cast<HMODULE>(modBase);
}

inline HMODULE LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE /*hFile*/, DWORD /*dwFlags*/) noexcept {
    return LoadLibraryW(lpLibFileName);
}

/**
 * @brief Retrieves the address of an exported function or variable from the specified DLL.
 */
inline void* GetProcAddress(HMODULE hModule, LPCSTR lpProcName) noexcept {
    if (!hModule || !lpProcName) return nullptr;
    void* procAddr = nullptr;
    NtStatus status = ntdll::LdrGetProcedureAddress(reinterpret_cast<uintptr_t>(hModule), lpProcName, 0, &procAddr);
    if (!NT_SUCCESS(status)) return nullptr;
    return procAddr;
}

/**
 * @brief Frees the loaded dynamic-link library (DLL) module.
 */
inline BOOL FreeLibrary(HMODULE hLibModule) noexcept {
    (void)hLibModule;
    return TRUE;
}

// ============================================================================
// 9. Error Handling & Thread-Local Status (Defined in Section 1)
// ============================================================================

// ============================================================================
// 10. Environment, Command Line & Working Directory
// ============================================================================

static std::unordered_map<std::wstring, std::wstring> g_EnvironmentVariables = {
    { L"OS", L"MicaNT" },
    { L"SystemRoot", L"C:\\Windows" },
    { L"windir", L"C:\\Windows" },
    { L"ComSpec", L"C:\\Windows\\System32\\cmd.exe" },
    { L"PATH", L"C:\\Windows\\System32;C:\\Windows" },
    { L"NUMBER_OF_PROCESSORS", L"4" },
    { L"PROCESSOR_ARCHITECTURE", L"AMD64" },
    { L"PROCESSOR_IDENTIFIER", L"AMD64 Family 6 Model 0 Stepping 0, MicaNT" },
    { L"USERPROFILE", L"C:\\Users\\Default" },
    { L"HOMEDRIVE", L"C:" },
    { L"HOMEPATH", L"\\Users\\Default" },
    { L"PROMPT", L"$P$G" }
};
static std::wstring g_CurrentDirectory = L"C:\\Windows\\System32";
static const wchar_t* g_CommandLineW = L"micant.exe";
static const char* g_CommandLineA = "micant.exe";

inline LPCSTR GetCommandLineA() noexcept { return g_CommandLineA; }
inline LPCWSTR GetCommandLineW() noexcept { return g_CommandLineW; }

inline DWORD GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize) noexcept {
    if (!lpName) {
        SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    auto it = g_EnvironmentVariables.find(lpName);
    if (it == g_EnvironmentVariables.end()) {
        SetLastError(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    }
    const auto& val = it->second;
    if (nSize <= val.size()) {
        return static_cast<DWORD>(val.size() + 1);
    }
    if (lpBuffer) {
        std::wcsncpy(lpBuffer, val.c_str(), nSize);
        return static_cast<DWORD>(val.size());
    }
    return 0;
}

inline DWORD GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) noexcept {
    if (!lpName) {
        SetLastError(87);
        return 0;
    }
    std::string nameStr(lpName);
    std::wstring wName(nameStr.begin(), nameStr.end());
    std::vector<wchar_t> wBuf(nSize ? nSize : 1);
    DWORD res = GetEnvironmentVariableW(wName.c_str(), wBuf.data(), nSize);
    if (res > 0 && res < nSize && lpBuffer) {
        for (DWORD i = 0; i < res; ++i) {
            lpBuffer[i] = static_cast<char>(wBuf[i]);
        }
        lpBuffer[res] = '\0';
    }
    return res;
}

inline BOOL SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue) noexcept {
    if (!lpName) {
        SetLastError(87);
        return FALSE;
    }
    if (!lpValue) {
        g_EnvironmentVariables.erase(lpName);
    } else {
        g_EnvironmentVariables[lpName] = lpValue;
    }
    return TRUE;
}

inline BOOL SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue) noexcept {
    if (!lpName) return FALSE;
    std::string nameStr(lpName);
    std::wstring wName(nameStr.begin(), nameStr.end());
    if (!lpValue) {
        return SetEnvironmentVariableW(wName.c_str(), nullptr);
    }
    std::string valStr(lpValue);
    std::wstring wVal(valStr.begin(), valStr.end());
    return SetEnvironmentVariableW(wName.c_str(), wVal.c_str());
}

inline DWORD GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer) noexcept {
    if (nBufferLength <= g_CurrentDirectory.size()) {
        return static_cast<DWORD>(g_CurrentDirectory.size() + 1);
    }
    if (lpBuffer) {
        std::wcsncpy(lpBuffer, g_CurrentDirectory.c_str(), nBufferLength);
        return static_cast<DWORD>(g_CurrentDirectory.size());
    }
    return 0;
}

inline DWORD GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer) noexcept {
    if (nBufferLength <= g_CurrentDirectory.size()) {
        return static_cast<DWORD>(g_CurrentDirectory.size() + 1);
    }
    if (lpBuffer) {
        for (size_t i = 0; i < g_CurrentDirectory.size(); ++i) {
            lpBuffer[i] = static_cast<char>(g_CurrentDirectory[i]);
        }
        lpBuffer[g_CurrentDirectory.size()] = '\0';
        return static_cast<DWORD>(g_CurrentDirectory.size());
    }
    return 0;
}

inline BOOL SetCurrentDirectoryW(LPCWSTR lpPathName) noexcept {
    if (!lpPathName) {
        SetLastError(87);
        return FALSE;
    }
    g_CurrentDirectory = lpPathName;
    return TRUE;
}

inline BOOL SetCurrentDirectoryA(LPCSTR lpPathName) noexcept {
    if (!lpPathName) return FALSE;
    std::string pathStr(lpPathName);
    std::wstring wPath(pathStr.begin(), pathStr.end());
    return SetCurrentDirectoryW(wPath.c_str());
}

inline DWORD GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR* lpFilePart) noexcept {
    if (!lpFileName) return 0;
    std::wstring fullPath;
    if (lpFileName[0] == L'\\' || (lpFileName[0] != L'\0' && lpFileName[1] == L':')) {
        fullPath = lpFileName;
    } else {
        fullPath = g_CurrentDirectory + L"\\" + lpFileName;
    }
    if (nBufferLength <= fullPath.size()) {
        return static_cast<DWORD>(fullPath.size() + 1);
    }
    if (lpBuffer) {
        std::wcsncpy(lpBuffer, fullPath.c_str(), nBufferLength);
        if (lpFilePart) {
            size_t slash = fullPath.find_last_of(L"\\/");
            *lpFilePart = (slash == std::wstring::npos) ? lpBuffer : (lpBuffer + slash + 1);
        }
        return static_cast<DWORD>(fullPath.size());
    }
    return 0;
}

inline DWORD GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR* lpFilePart) noexcept {
    if (!lpFileName) return 0;
    std::string nameStr(lpFileName);
    std::wstring wName(nameStr.begin(), nameStr.end());
    std::vector<wchar_t> wBuf(nBufferLength ? nBufferLength : 1);
    wchar_t* wPart = nullptr;
    DWORD res = GetFullPathNameW(wName.c_str(), nBufferLength, wBuf.data(), &wPart);
    if (res > 0 && res < nBufferLength && lpBuffer) {
        for (DWORD i = 0; i < res; ++i) {
            lpBuffer[i] = static_cast<char>(wBuf[i]);
        }
        lpBuffer[res] = '\0';
        if (lpFilePart && wPart) {
            *lpFilePart = lpBuffer + (wPart - wBuf.data());
        }
    }
    return res;
}

// ============================================================================
// 11. Module & Process Introspection
// ============================================================================


inline DWORD GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) noexcept {
    if (!lpFilename || nSize == 0) return 0;
    std::wstring path = L"C:\\Windows\\System32\\micant.exe";
    if (hModule == reinterpret_cast<HMODULE>(0x7FF800000000ULL)) {
        path = L"C:\\Windows\\System32\\kernel32.dll";
    } else if (hModule == reinterpret_cast<HMODULE>(0x7FF810000000ULL)) {
        path = L"C:\\Windows\\System32\\ntdll.dll";
    }
    size_t copyLen = std::min<size_t>(path.size(), nSize - 1);
    std::wcsncpy(lpFilename, path.c_str(), copyLen);
    lpFilename[copyLen] = L'\0';
    return static_cast<DWORD>(copyLen);
}

inline DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize) noexcept {
    if (!lpFilename || nSize == 0) return 0;
    std::vector<wchar_t> wBuf(nSize);
    DWORD res = GetModuleFileNameW(hModule, wBuf.data(), nSize);
    for (DWORD i = 0; i < res; ++i) {
        lpFilename[i] = static_cast<char>(wBuf[i]);
    }
    lpFilename[res] = '\0';
    return res;
}

inline HMODULE GetModuleHandleW(LPCWSTR lpModuleName) noexcept {
    if (!lpModuleName) {
        if (g_CurrentExecutableBase != 0) return reinterpret_cast<HMODULE>(g_CurrentExecutableBase);
        return reinterpret_cast<HMODULE>(0x140000000ULL);
    }
    std::wstring name(lpModuleName);
    for (auto& c : name) c = static_cast<wchar_t>(std::towlower(c));
    if (name.find(L'.') == std::wstring::npos) {
        name += L".dll";
    }

    // Check already loaded modules in DynamicLoader
    for (const auto& mod : ldr::DynamicLoader::get().getLoadedModules()) {
        std::wstring modBase(mod->storedBaseName);
        for (auto& c : modBase) c = static_cast<wchar_t>(std::towlower(c));
        if (modBase == name || mod->storedFullName == name) {
            return reinterpret_cast<HMODULE>(mod->dllBase);
        }
    }

    if (name == L"kernel32.dll") {
        return reinterpret_cast<HMODULE>(0x7FF800000000ULL);
    }
    if (name == L"ntdll.dll") {
        return reinterpret_cast<HMODULE>(0x7FF810000000ULL);
    }

    // Register/load module in DynamicLoader table
    UnicodeString uniName(name.c_str());
    uintptr_t modBase = 0;
    if (NT_SUCCESS(ntdll::LdrLoadDll(nullptr, 0, &uniName, &modBase))) {
        return reinterpret_cast<HMODULE>(modBase);
    }

    if (g_CurrentExecutableBase != 0) return reinterpret_cast<HMODULE>(g_CurrentExecutableBase);
    return reinterpret_cast<HMODULE>(0x140000000ULL);
}

inline HMODULE GetModuleHandleA(LPCSTR lpModuleName) noexcept {
    if (!lpModuleName) return GetModuleHandleW(nullptr);
    std::string modStr(lpModuleName);
    std::wstring wMod(modStr.begin(), modStr.end());
    return GetModuleHandleW(wMod.c_str());
}

inline BOOL GetModuleHandleExW(DWORD /*dwFlags*/, LPCWSTR lpModuleName, HMODULE* phModule) noexcept {
    if (!phModule) return FALSE;
    *phModule = GetModuleHandleW(lpModuleName);
    return TRUE;
}

// ============================================================================
// 12. Extended File Operations, Sizing, Seeking & Directories
// ============================================================================

inline DWORD GetFileAttributesW(LPCWSTR lpFileName) noexcept {
    if (!lpFileName) return INVALID_FILE_ATTRIBUTES;
    uint32_t attrs = 0;
    NtStatus status = fs::VirtualFileSystem::get().queryFileAttributes(lpFileName, attrs);
    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return INVALID_FILE_ATTRIBUTES;
    }
    return attrs;
}

inline DWORD GetFileAttributesA(LPCSTR lpFileName) noexcept {
    if (!lpFileName) return INVALID_FILE_ATTRIBUTES;
    std::string nameStr(lpFileName);
    std::wstring wName(nameStr.begin(), nameStr.end());
    return GetFileAttributesW(wName.c_str());
}

inline BOOL SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes) noexcept {
    if (!lpFileName) return FALSE;
    NtStatus status = fs::VirtualFileSystem::get().setFileAttributes(lpFileName, dwFileAttributes);
    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }
    return TRUE;
}

inline BOOL GetFileSizeEx(HANDLE hFile, LargeInteger* lpFileSize) noexcept {
    if (!hFile || !lpFileSize) {
        SetLastError(87);
        return FALSE;
    }
    IoStatusBlock iosb{};
    FileStandardInformation stdInfo{};
    NtStatus status = ntdll::NtQueryInformationFile(
        reinterpret_cast<Handle>(hFile),
        &iosb,
        &stdInfo,
        sizeof(stdInfo),
        FileInformationClass::FileStandardInformation
    );
    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }
    *lpFileSize = stdInfo.endOfFile;
    return TRUE;
}

inline DWORD GetFileSize(HANDLE hFile, DWORD* lpFileSizeHigh) noexcept {
    LargeInteger li{};
    if (!GetFileSizeEx(hFile, &li)) return INVALID_FILE_SIZE;
    if (lpFileSizeHigh) *lpFileSizeHigh = static_cast<DWORD>(li.highPart);
    return li.lowPart;
}

inline BOOL SetFilePointerEx(HANDLE hFile, LargeInteger liDistanceToMove, LargeInteger* lpNewFilePointer, DWORD dwMoveMethod) noexcept {
    if (!hFile) {
        SetLastError(6); // ERROR_INVALID_HANDLE
        return FALSE;
    }

    int64_t targetOffset = 0;
    if (dwMoveMethod == FILE_BEGIN) {
        targetOffset = liDistanceToMove.quadPart;
    } else if (dwMoveMethod == FILE_CURRENT) {
        IoStatusBlock iosb{};
        FilePositionInformation posInfo{};
        ntdll::NtQueryInformationFile(reinterpret_cast<Handle>(hFile), &iosb, &posInfo, sizeof(posInfo), FileInformationClass::FilePositionInformation);
        targetOffset = posInfo.currentByteOffset.quadPart + liDistanceToMove.quadPart;
    } else if (dwMoveMethod == FILE_END) {
        LargeInteger sz{};
        if (!GetFileSizeEx(hFile, &sz)) return FALSE;
        targetOffset = sz.quadPart + liDistanceToMove.quadPart;
    } else {
        SetLastError(87);
        return FALSE;
    }

    if (targetOffset < 0) targetOffset = 0;

    IoStatusBlock iosb{};
    FilePositionInformation posInfo{};
    posInfo.currentByteOffset.quadPart = targetOffset;
    NtStatus status = ntdll::NtSetInformationFile(
        reinterpret_cast<Handle>(hFile),
        &iosb,
        &posInfo,
        sizeof(posInfo),
        FileInformationClass::FilePositionInformation
    );

    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }

    if (lpNewFilePointer) {
        lpNewFilePointer->quadPart = targetOffset;
    }
    return TRUE;
}

inline DWORD SetFilePointer(HANDLE hFile, int32_t lDistanceToMove, int32_t* lpDistanceToMoveHigh, DWORD dwMoveMethod) noexcept {
    LargeInteger move{}, newPos{};
    move.lowPart = static_cast<uint32_t>(lDistanceToMove);
    move.highPart = lpDistanceToMoveHigh ? *lpDistanceToMoveHigh : (lDistanceToMove < 0 ? -1 : 0);
    if (!SetFilePointerEx(hFile, move, &newPos, dwMoveMethod)) return INVALID_FILE_SIZE;
    if (lpDistanceToMoveHigh) *lpDistanceToMoveHigh = newPos.highPart;
    return newPos.lowPart;
}

inline BOOL DeleteFileW(LPCWSTR lpFileName) noexcept {
    if (!lpFileName) return FALSE;
    NtStatus status = fs::VirtualFileSystem::get().deleteFile(lpFileName);
    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }
    return TRUE;
}

inline BOOL DeleteFileA(LPCSTR lpFileName) noexcept {
    if (!lpFileName) return FALSE;
    std::string s(lpFileName);
    std::wstring w(s.begin(), s.end());
    return DeleteFileW(w.c_str());
}

inline BOOL CopyFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) noexcept {
    if (!lpExistingFileName || !lpNewFileName) {
        SetLastError(87);
        return FALSE;
    }
    if (bFailIfExists) {
        uint32_t attrs = 0;
        if (NT_SUCCESS(fs::VirtualFileSystem::get().queryFileAttributes(lpNewFileName, attrs))) {
            SetLastError(80); // ERROR_FILE_EXISTS
            return FALSE;
        }
    }
    std::shared_ptr<fs::FileObject> srcObj;
    NtStatus st = fs::VirtualFileSystem::get().createOrOpenFile(lpExistingFileName, fs::FILE_GENERIC_READ, fs::FILE_OPEN, srcObj);
    if (!NT_SUCCESS(st) || !srcObj) {
        SetLastError(ntdll::RtlNtStatusToDosError(st));
        return FALSE;
    }
    std::shared_ptr<fs::FileObject> dstObj;
    st = fs::VirtualFileSystem::get().createOrOpenFile(lpNewFileName, fs::FILE_GENERIC_WRITE, fs::FILE_OVERWRITE_IF, dstObj);
    if (!NT_SUCCESS(st) || !dstObj) {
        SetLastError(ntdll::RtlNtStatusToDosError(st));
        return FALSE;
    }
    uint32_t written = 0;
    st = fs::VirtualFileSystem::get().writeFile(dstObj.get(), srcObj->getData().data(), static_cast<uint32_t>(srcObj->getData().size()), nullptr, written);
    fs::VirtualFileSystem::get().closeFile(srcObj.get());
    fs::VirtualFileSystem::get().closeFile(dstObj.get());
    if (!NT_SUCCESS(st)) {
        SetLastError(ntdll::RtlNtStatusToDosError(st));
        return FALSE;
    }
    return TRUE;
}

inline BOOL CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists) noexcept {
    if (!lpExistingFileName || !lpNewFileName) return FALSE;
    std::string sSrc(lpExistingFileName);
    std::string sDst(lpNewFileName);
    std::wstring wSrc(sSrc.begin(), sSrc.end());
    std::wstring wDst(sDst.begin(), sDst.end());
    return CopyFileW(wSrc.c_str(), wDst.c_str(), bFailIfExists);
}

inline BOOL MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) noexcept {
    if (!lpExistingFileName || !lpNewFileName) {
        SetLastError(87);
        return FALSE;
    }
    if (!CopyFileW(lpExistingFileName, lpNewFileName, FALSE)) {
        return FALSE;
    }
    return DeleteFileW(lpExistingFileName);
}

inline BOOL MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName) noexcept {
    if (!lpExistingFileName || !lpNewFileName) return FALSE;
    std::string sSrc(lpExistingFileName);
    std::string sDst(lpNewFileName);
    std::wstring wSrc(sSrc.begin(), sSrc.end());
    std::wstring wDst(sDst.begin(), sDst.end());
    return MoveFileW(wSrc.c_str(), wDst.c_str());
}

inline BOOL MoveFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD /*dwFlags*/) noexcept {
    return MoveFileW(lpExistingFileName, lpNewFileName);
}

inline BOOL CreateDirectoryW(LPCWSTR lpPathName, void* /*lpSecurityAttributes*/) noexcept {
    if (!lpPathName) return FALSE;
    NtStatus status = fs::VirtualFileSystem::get().createDirectory(lpPathName);
    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }
    return TRUE;
}

inline BOOL CreateDirectoryA(LPCSTR lpPathName, void* lpSecurityAttributes) noexcept {
    if (!lpPathName) return FALSE;
    std::string s(lpPathName);
    std::wstring w(s.begin(), s.end());
    return CreateDirectoryW(w.c_str(), lpSecurityAttributes);
}

inline BOOL RemoveDirectoryW(LPCWSTR lpPathName) noexcept {
    if (!lpPathName) return FALSE;
    NtStatus status = fs::VirtualFileSystem::get().removeDirectory(lpPathName);
    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return FALSE;
    }
    return TRUE;
}

inline BOOL RemoveDirectoryA(LPCSTR lpPathName) noexcept {
    if (!lpPathName) return FALSE;
    std::string s(lpPathName);
    std::wstring w(s.begin(), s.end());
    return RemoveDirectoryW(w.c_str());
}

// FindFile Context Registry
struct FindFileContext {
    std::wstring directoryPath;
    std::vector<fs::VirtualFileSystem::DirectoryEntry> entries;
    size_t currentIndex{0};
};

static std::unordered_map<HANDLE, std::unique_ptr<FindFileContext>> g_FindContexts;
static uintptr_t g_NextFindHandle = 0x500;

inline HANDLE FindFirstFileW(LPCWSTR lpFileName, WIN32_FIND_DATAW* lpFindFileData) noexcept {
    if (!lpFileName || !lpFindFileData) {
        SetLastError(87);
        return INVALID_HANDLE_VALUE;
    }

    std::wstring path(lpFileName);
    size_t lastSlash = path.find_last_of(L"\\/");
    std::wstring dir = (lastSlash == std::wstring::npos) ? L"" : path.substr(0, lastSlash);

    std::vector<fs::VirtualFileSystem::DirectoryEntry> entries;
    NtStatus status = fs::VirtualFileSystem::get().queryDirectory(dir, entries);
    if (!NT_SUCCESS(status) || entries.empty()) {
        SetLastError(2); // ERROR_FILE_NOT_FOUND
        return INVALID_HANDLE_VALUE;
    }

    auto ctx = std::make_unique<FindFileContext>();
    ctx->directoryPath = dir;
    ctx->entries = std::move(entries);
    ctx->currentIndex = 0;

    const auto& first = ctx->entries[0];
    *lpFindFileData = WIN32_FIND_DATAW{};
    lpFindFileData->dwFileAttributes = first.attributes;
    lpFindFileData->nFileSizeLow = static_cast<DWORD>(first.size);
    std::wcsncpy(lpFindFileData->cFileName, first.name.c_str(), 259);

    HANDLE hFind = reinterpret_cast<HANDLE>(g_NextFindHandle++);
    g_FindContexts[hFind] = std::move(ctx);
    return hFind;
}

inline BOOL FindNextFileW(HANDLE hFindFile, WIN32_FIND_DATAW* lpFindFileData) noexcept {
    if (!hFindFile || !lpFindFileData) {
        SetLastError(87);
        return FALSE;
    }
    auto it = g_FindContexts.find(hFindFile);
    if (it == g_FindContexts.end()) {
        SetLastError(6); // ERROR_INVALID_HANDLE
        return FALSE;
    }

    auto& ctx = it->second;
    ctx->currentIndex++;
    if (ctx->currentIndex >= ctx->entries.size()) {
        SetLastError(18); // ERROR_NO_MORE_FILES
        return FALSE;
    }

    const auto& entry = ctx->entries[ctx->currentIndex];
    *lpFindFileData = WIN32_FIND_DATAW{};
    lpFindFileData->dwFileAttributes = entry.attributes;
    lpFindFileData->nFileSizeLow = static_cast<DWORD>(entry.size);
    std::wcsncpy(lpFindFileData->cFileName, entry.name.c_str(), 259);
    return TRUE;
}

inline BOOL FindClose(HANDLE hFindFile) noexcept {
    if (!hFindFile) return FALSE;
    return g_FindContexts.erase(hFindFile) > 0 ? TRUE : FALSE;
}

// ============================================================================
// 13. High-Precision Timing & System Clock
// ============================================================================

inline BOOL QueryPerformanceCounter(LargeInteger* lpPerformanceCount) noexcept {
    if (!lpPerformanceCount) return FALSE;
    ntdll::NtQueryPerformanceCounter(lpPerformanceCount, nullptr);
    return TRUE;
}

inline BOOL QueryPerformanceFrequency(LargeInteger* lpFrequency) noexcept {
    if (!lpFrequency) return FALSE;
    LargeInteger count{};
    ntdll::NtQueryPerformanceCounter(&count, lpFrequency);
    return TRUE;
}

inline void GetSystemTime(SYSTEMTIME* lpSystemTime) noexcept {
    if (!lpSystemTime) return;
    *lpSystemTime = SYSTEMTIME{};
}

inline void GetLocalTime(SYSTEMTIME* lpSystemTime) noexcept {
    GetSystemTime(lpSystemTime);
}

// ============================================================================
// 14. Console Control Enhancements
// ============================================================================

inline BOOL GetConsoleMode(HANDLE /*hConsoleHandle*/, DWORD* lpMode) noexcept {
    if (!lpMode) return FALSE;
    *lpMode = ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    return TRUE;
}

inline BOOL SetConsoleMode(HANDLE /*hConsoleHandle*/, DWORD /*dwMode*/) noexcept {
    return TRUE;
}

inline uint32_t GetConsoleOutputCP() noexcept {
    return 65001; // UTF-8
}

inline std::shared_ptr<conhost::ConsoleSession> GetActiveConsoleSession() noexcept {
    DWORD pid = GetCurrentProcessId();
    auto session = conhost::ConhostManager::get().getConsole(pid);
    if (!session) {
        session = conhost::ConhostManager::get().allocateConsole(pid);
    }
    return session;
}

inline BOOL GetConsoleScreenBufferInfo(HANDLE /*hConsoleOutput*/, conhost::ConsoleScreenBufferInfo* lpConsoleScreenBufferInfo) noexcept {
    if (!lpConsoleScreenBufferInfo) return FALSE;
    auto session = GetActiveConsoleSession();
    if (!session) return FALSE;
    *lpConsoleScreenBufferInfo = session->getScreenBuffer().getScreenBufferInfo();
    return TRUE;
}

inline BOOL SetConsoleTextAttribute(HANDLE /*hConsoleOutput*/, uint16_t wAttributes) noexcept {
    auto session = GetActiveConsoleSession();
    if (!session) return FALSE;
    session->getScreenBuffer().setAttributes(wAttributes);
    return TRUE;
}

inline BOOL SetConsoleCursorPosition(HANDLE /*hConsoleOutput*/, conhost::Coord dwCursorPosition) noexcept {
    auto session = GetActiveConsoleSession();
    if (!session) return FALSE;
    session->getScreenBuffer().setCursorPosition(dwCursorPosition);
    return TRUE;
}

inline BOOL WriteConsoleA(
    HANDLE hConsoleOutput,
    const void* lpBuffer,
    DWORD nNumberOfCharsToWrite,
    DWORD* lpNumberOfCharsWritten,
    LPVOID /*lpReserved*/
) noexcept {
    if (!lpBuffer || nNumberOfCharsToWrite == 0) {
        if (lpNumberOfCharsWritten) *lpNumberOfCharsWritten = 0;
        return TRUE;
    }
    const char* str = reinterpret_cast<const char*>(lpBuffer);
    std::wstring wstr(str, str + nNumberOfCharsToWrite);
    return WriteConsoleW(hConsoleOutput, wstr.data(), nNumberOfCharsToWrite, lpNumberOfCharsWritten, nullptr);
}

// ============================================================================
// 15. Memory Mapping & Section Objects
// ============================================================================

inline HANDLE CreateFileMappingW(
    HANDLE hFile,
    void* /*lpFileMappingAttributes*/,
    DWORD flProtect,
    DWORD dwMaximumSizeHigh,
    DWORD dwMaximumSizeLow,
    LPCWSTR lpName
) noexcept {
    LargeInteger maxSz{};
    maxSz.lowPart = dwMaximumSizeLow;
    maxSz.highPart = static_cast<int32_t>(dwMaximumSizeHigh);

    UnicodeString uniName(lpName);
    ObjectAttributes objAttr{};
    if (lpName) objAttr.objectName = &uniName;

    Handle hSec = 0;
    Handle fHandle = (hFile == INVALID_HANDLE_VALUE) ? 0 : reinterpret_cast<Handle>(hFile);
    NtStatus status = ntdll::NtCreateSection(
        &hSec,
        0xF001F, // SECTION_ALL_ACCESS
        &objAttr,
        (maxSz.quadPart > 0) ? &maxSz : nullptr,
        flProtect ? flProtect : 0x04 /* PAGE_READWRITE */,
        0x08000000 /* SEC_COMMIT */,
        fHandle
    );

    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return nullptr;
    }
    return reinterpret_cast<HANDLE>(hSec);
}

inline LPVOID MapViewOfFile(
    HANDLE hFileMappingObject,
    DWORD /*dwDesiredAccess*/,
    DWORD /*dwFileOffsetHigh*/,
    DWORD /*dwFileOffsetLow*/,
    SIZE_T dwNumberOfBytesToMap
) noexcept {
    if (!hFileMappingObject) return nullptr;
    uintptr_t baseAddr = 0;
    size_t viewSize = dwNumberOfBytesToMap;
    NtStatus status = ntdll::NtMapViewOfSection(
        reinterpret_cast<Handle>(hFileMappingObject),
        static_cast<Handle>(-1), // CurrentProcess
        &baseAddr,
        0,
        viewSize,
        nullptr,
        &viewSize,
        1,
        0x3000, // MEM_COMMIT | MEM_RESERVE
        0x04    // PAGE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        SetLastError(ntdll::RtlNtStatusToDosError(status));
        return nullptr;
    }
    return reinterpret_cast<LPVOID>(baseAddr);
}

inline BOOL UnmapViewOfFile(LPCVOID lpBaseAddress) noexcept {
    if (!lpBaseAddress) return FALSE;
    NtStatus status = ntdll::NtUnmapViewOfSection(
        static_cast<Handle>(-1),
        reinterpret_cast<uintptr_t>(lpBaseAddress)
    );
    return NT_SUCCESS(status) ? TRUE : FALSE;
}


// ============================================================================
// 16. Process & Thread Operations
// ============================================================================

inline BOOL GetExitCodeProcess(HANDLE hProcess, DWORD* lpExitCode) noexcept {
    if (!hProcess || !lpExitCode) return FALSE;
    ProcessBasicInformation pbi{};
    NtStatus status = ntdll::NtQueryInformationProcess(
        reinterpret_cast<Handle>(hProcess),
        ProcessInformationClass::ProcessBasicInformation,
        &pbi,
        sizeof(pbi)
    );
    if (NT_SUCCESS(status)) {
        *lpExitCode = static_cast<DWORD>(pbi.exitStatus);
        return TRUE;
    }
    *lpExitCode = 0;
    return TRUE;
}

inline BOOL TerminateProcess(HANDLE hProcess, DWORD uExitCode) noexcept {
    if (!hProcess) return FALSE;
    if (hProcess == GetCurrentProcess()) {
        ExitProcess(uExitCode);
    }
    NtStatus status = ntdll::NtTerminateProcess(reinterpret_cast<Handle>(hProcess), static_cast<NtStatus>(uExitCode));
    return NT_SUCCESS(status) ? TRUE : FALSE;
}

inline BOOL SwitchToThread() noexcept {
    ntdll::NtYieldExecution();
    return TRUE;
}

// ============================================================================
// 17. CRT Startup & Advanced Win32 Interop Support
// ============================================================================

struct FILETIME {
    DWORD dwLowDateTime{0};
    DWORD dwHighDateTime{0};
};
using PFILETIME = FILETIME*;
using LPFILETIME = FILETIME*;

inline void GetSystemTimeAsFileTime(FILETIME* lpTime) noexcept {
    if (!lpTime) return;
    uint64_t ft = 133500000000000000ULL + GetTickCount64() * 10000ULL;
    lpTime->dwLowDateTime = static_cast<DWORD>(ft & 0xFFFFFFFF);
    lpTime->dwHighDateTime = static_cast<DWORD>(ft >> 32);
}

inline void InitializeSListHead(void* /*ListHead*/) noexcept {}

inline std::unordered_map<uint32_t, void*> g_FlsSlots;
inline std::mutex g_FlsMutex;
inline uint32_t g_NextFls = 1;

inline uint32_t FlsAlloc(void* /*lpCallback*/) noexcept {
    std::lock_guard<std::mutex> lock(g_FlsMutex);
    uint32_t idx = g_NextFls++;
    g_FlsSlots[idx] = nullptr;
    return idx;
}

inline void* FlsGetValue(uint32_t dwFlsIndex) noexcept {
    std::lock_guard<std::mutex> lock(g_FlsMutex);
    auto it = g_FlsSlots.find(dwFlsIndex);
    if (it != g_FlsSlots.end()) {
        return it->second;
    }
    return nullptr;
}

inline BOOL FlsSetValue(uint32_t dwFlsIndex, void* lpFlsData) noexcept {
    std::lock_guard<std::mutex> lock(g_FlsMutex);
    g_FlsSlots[dwFlsIndex] = lpFlsData;
    return TRUE;
}

inline BOOL FlsFree(uint32_t dwFlsIndex) noexcept {
    std::lock_guard<std::mutex> lock(g_FlsMutex);
    g_FlsSlots.erase(dwFlsIndex);
    return TRUE;
}

inline thread_local void* g_TlsSlots[64]{};

inline DWORD TlsAlloc() noexcept {
    static std::atomic<DWORD> s_TlsIndex{0};
    return s_TlsIndex.fetch_add(1);
}

inline LPVOID TlsGetValue(DWORD dwTlsIndex) noexcept {
    if (dwTlsIndex < 64) return g_TlsSlots[dwTlsIndex];
    return nullptr;
}

inline BOOL TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue) noexcept {
    if (dwTlsIndex < 64) {
        g_TlsSlots[dwTlsIndex] = lpTlsValue;
        return TRUE;
    }
    return FALSE;
}

inline BOOL TlsFree(DWORD /*dwTlsIndex*/) noexcept {
    return TRUE;
}

inline void InitializeCriticalSection(void* /*cs*/) noexcept {}
inline BOOL InitializeCriticalSectionEx(void* /*cs*/, uint32_t /*spin*/, uint32_t /*flags*/) noexcept { return TRUE; }
inline void EnterCriticalSection(void* /*cs*/) noexcept {}
inline void LeaveCriticalSection(void* /*cs*/) noexcept {}
inline void DeleteCriticalSection(void* /*cs*/) noexcept {}

inline void* EncodePointer(void* ptr) noexcept { return ptr; }
inline void* DecodePointer(void* ptr) noexcept { return ptr; }

struct STARTUPINFOW {
    DWORD cb{sizeof(STARTUPINFOW)};
    LPWSTR lpReserved{nullptr};
    LPWSTR lpDesktop{nullptr};
    LPWSTR lpTitle{nullptr};
    DWORD dwX{0}, dwY{0}, dwXSize{80}, dwYSize{25};
    DWORD dwXCountChars{80}, dwYCountChars{25};
    DWORD dwFillAttribute{0x07};
    DWORD dwFlags{0};
    uint16_t wShowWindow{0};
    uint16_t cbReserved2{0};
    uint8_t* lpReserved2{nullptr};
    HANDLE hStdInput{GetStdHandle(STD_INPUT_HANDLE)};
    HANDLE hStdOutput{GetStdHandle(STD_OUTPUT_HANDLE)};
    HANDLE hStdError{GetStdHandle(STD_ERROR_HANDLE)};
};

inline void GetStartupInfoW(STARTUPINFOW* si) noexcept {
    if (si) *si = STARTUPINFOW{};
}

struct STARTUPINFOA {
    DWORD   cb{sizeof(STARTUPINFOA)};
    LPSTR   lpReserved{nullptr};
    LPSTR   lpDesktop{nullptr};
    LPSTR   lpTitle{nullptr};
    DWORD   dwX{0};
    DWORD   dwY{0};
    DWORD   dwXSize{0};
    DWORD   dwYSize{0};
    DWORD   dwXCountChars{0};
    DWORD   dwYCountChars{0};
    DWORD   dwFillAttribute{0};
    DWORD   dwFlags{0};
    uint16_t wShowWindow{0};
    uint16_t cbReserved2{0};
    uint8_t* lpReserved2{nullptr};
    HANDLE  hStdInput{nullptr};
    HANDLE  hStdOutput{nullptr};
    HANDLE  hStdError{nullptr};
};

struct PROCESS_INFORMATION {
    HANDLE hProcess{nullptr};
    HANDLE hThread{nullptr};
    DWORD  dwProcessId{0};
    DWORD  dwThreadId{0};
};

struct SECURITY_ATTRIBUTES {
    DWORD  nLength{sizeof(SECURITY_ATTRIBUTES)};
    LPVOID lpSecurityDescriptor{nullptr};
    BOOL   bInheritHandle{0};
};

inline BOOL CreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    SECURITY_ATTRIBUTES* /*lpProcessAttributes*/,
    SECURITY_ATTRIBUTES* /*lpThreadAttributes*/,
    BOOL /*bInheritHandles*/,
    DWORD /*dwCreationFlags*/,
    LPVOID /*lpEnvironment*/,
    LPCWSTR /*lpCurrentDirectory*/,
    STARTUPINFOW* /*lpStartupInfo*/,
    PROCESS_INFORMATION* lpProcessInformation
) noexcept {
    std::wstring imgName;
    if (lpApplicationName && *lpApplicationName) {
        imgName = lpApplicationName;
    } else if (lpCommandLine && *lpCommandLine) {
        imgName = lpCommandLine;
    } else {
        return FALSE;
    }

    auto proc = ps::ProcessManager::get().createProcess(imgName);
    if (!proc) return FALSE;

    if (lpProcessInformation) {
        lpProcessInformation->hProcess = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(proc->getPid()));
        lpProcessInformation->hThread  = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x80000000ULL | proc->getPid()));
        lpProcessInformation->dwProcessId = static_cast<DWORD>(proc->getPid());
        lpProcessInformation->dwThreadId  = static_cast<DWORD>(1);
    }
    return TRUE;
}

inline BOOL CreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    SECURITY_ATTRIBUTES* lpProcessAttributes,
    SECURITY_ATTRIBUTES* lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    STARTUPINFOA* lpStartupInfo,
    PROCESS_INFORMATION* lpProcessInformation
) noexcept {
    std::wstring wApp, wCmd, wDir;
    if (lpApplicationName) wApp.assign(lpApplicationName, lpApplicationName + std::strlen(lpApplicationName));
    if (lpCommandLine) wCmd.assign(lpCommandLine, lpCommandLine + std::strlen(lpCommandLine));
    if (lpCurrentDirectory) wDir.assign(lpCurrentDirectory, lpCurrentDirectory + std::strlen(lpCurrentDirectory));

    STARTUPINFOW siW{};
    if (lpStartupInfo) {
        siW.cb = sizeof(siW);
        siW.dwFlags = lpStartupInfo->dwFlags;
        siW.wShowWindow = lpStartupInfo->wShowWindow;
    }

    return CreateProcessW(
        wApp.empty() ? nullptr : wApp.c_str(),
        wCmd.empty() ? nullptr : wCmd.data(),
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        wDir.empty() ? nullptr : wDir.c_str(),
        &siW,
        lpProcessInformation
    );
}


inline DWORD GetFileType(HANDLE hFile) noexcept {
    if (hFile == GetStdHandle(STD_OUTPUT_HANDLE) || 
        hFile == GetStdHandle(STD_INPUT_HANDLE) || 
        hFile == GetStdHandle(STD_ERROR_HANDLE)) {
        return 0x0002; // FILE_TYPE_CHAR
    }
    return 0x0001; // FILE_TYPE_DISK
}

inline BOOL IsProcessorFeaturePresent(DWORD /*ProcessorFeature*/) noexcept {
    return TRUE; // x86-64 standard extensions
}

inline BOOL IsDebuggerPresent() noexcept {
    return FALSE;
}

inline void* SetUnhandledExceptionFilter(void* /*lpTopLevelExceptionFilter*/) noexcept {
    return nullptr;
}

inline int32_t UnhandledExceptionFilter(void* /*ExceptionInfo*/) noexcept {
    return 1; // EXCEPTION_EXECUTE_HANDLER
}

inline int MultiByteToWideChar(
    uint32_t /*CodePage*/,
    uint32_t /*dwFlags*/,
    LPCSTR lpMultiByteStr,
    int cbMultiByte,
    LPWSTR lpWideCharStr,
    int cchWideChar
) noexcept {
    if (!lpMultiByteStr) return 0;
    int srcLen = (cbMultiByte < 0) ? static_cast<int>(std::strlen(lpMultiByteStr) + 1) : cbMultiByte;
    if (cchWideChar == 0) return srcLen;
    int toCopy = std::min(srcLen, cchWideChar);
    for (int i = 0; i < toCopy; ++i) {
        lpWideCharStr[i] = static_cast<wchar_t>(static_cast<unsigned char>(lpMultiByteStr[i]));
    }
    return toCopy;
}

inline int WideCharToMultiByte(
    uint32_t /*CodePage*/,
    uint32_t /*dwFlags*/,
    LPCWSTR lpWideCharStr,
    int cchWideChar,
    LPSTR lpMultiByteStr,
    int cbMultiByte,
    LPCSTR /*lpDefaultChar*/,
    BOOL* /*lpUsedDefaultChar*/
) noexcept {
    if (!lpWideCharStr) return 0;
    int srcLen = (cchWideChar < 0) ? static_cast<int>(std::wcslen(lpWideCharStr) + 1) : cchWideChar;
    if (cbMultiByte == 0) return srcLen;
    int toCopy = std::min(srcLen, cbMultiByte);
    for (int i = 0; i < toCopy; ++i) {
        lpMultiByteStr[i] = static_cast<char>(lpWideCharStr[i] & 0x7F);
    }
    return toCopy;
}

inline uint32_t GetACP() noexcept { return 65001; }
inline uint32_t GetOEMCP() noexcept { return 65001; }
inline BOOL IsValidCodePage(uint32_t /*CodePage*/) noexcept { return TRUE; }
inline BOOL GetCPInfo(uint32_t /*CodePage*/, void* /*lpCPInfo*/) noexcept { return TRUE; }

inline int CompareStringW(uint32_t /*Locale*/, uint32_t /*dwCmpFlags*/, LPCWSTR lpString1, int cchCount1, LPCWSTR lpString2, int cchCount2) noexcept {
    if (!lpString1 || !lpString2) return 0;
    int len1 = (cchCount1 < 0) ? static_cast<int>(std::wcslen(lpString1)) : cchCount1;
    int len2 = (cchCount2 < 0) ? static_cast<int>(std::wcslen(lpString2)) : cchCount2;
    int cmp = std::wcsncmp(lpString1, lpString2, std::min(len1, len2));
    if (cmp < 0) return 1; // CSTR_LESS_THAN
    if (cmp > 0) return 3; // CSTR_GREATER_THAN
    if (len1 < len2) return 1;
    if (len1 > len2) return 3;
    return 2; // CSTR_EQUAL
}

inline int LCMapStringW(uint32_t /*Locale*/, uint32_t /*dwMapFlags*/, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest) noexcept {
    if (!lpSrcStr) return 0;
    int len = (cchSrc < 0) ? static_cast<int>(std::wcslen(lpSrcStr) + 1) : cchSrc;
    if (cchDest == 0) return len;
    int toCopy = std::min(len, cchDest);
    std::wcsncpy(lpDestStr, lpSrcStr, toCopy);
    return toCopy;
}

inline HANDLE FindFirstFileExW(
    LPCWSTR lpFileName,
    uint32_t /*fInfoLevelId*/,
    LPVOID lpFindFileData,
    uint32_t /*fSearchOp*/,
    LPVOID /*lpSearchFilter*/,
    DWORD /*dwAdditionalFlags*/
) noexcept {
    return FindFirstFileW(lpFileName, reinterpret_cast<WIN32_FIND_DATAW*>(lpFindFileData));
}

inline BOOL FlushFileBuffers(HANDLE /*hFile*/) noexcept {
    return TRUE;
}

inline LPWCH GetEnvironmentStringsW() noexcept {
    static const wchar_t s_EnvBlock[] = L"OS=MicaNT\0SystemRoot=C:\\Windows\0windir=C:\\Windows\0\0";
    return const_cast<LPWCH>(s_EnvBlock);
}

inline BOOL FreeEnvironmentStringsW(LPWCH /*penv*/) noexcept {
    return TRUE;
}

inline BOOL GetStringTypeW(DWORD /*dwInfoType*/, LPCWSTR /*lpSrcStr*/, int /*cchSrc*/, uint16_t* lpCharType) noexcept {
    if (lpCharType) *lpCharType = 0x0001; // C1_ALPHA
    return TRUE;
}

inline BOOL VirtualProtect(LPVOID /*lpAddress*/, SIZE_T /*dwSize*/, DWORD /*flNewProtect*/, DWORD* lpflOldProtect) noexcept {
    if (lpflOldProtect) *lpflOldProtect = 0x04; // PAGE_READWRITE
    return TRUE;
}

struct MEMORY_BASIC_INFORMATION {
    LPVOID BaseAddress;
    LPVOID AllocationBase;
    DWORD AllocationProtect;
    uint16_t PartitionId;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

inline SIZE_T VirtualQuery(LPCVOID lpAddress, MEMORY_BASIC_INFORMATION* lpBuffer, SIZE_T dwLength) noexcept {
    if (!lpBuffer || dwLength < sizeof(MEMORY_BASIC_INFORMATION)) return 0;
    lpBuffer->BaseAddress = const_cast<LPVOID>(lpAddress);
    lpBuffer->AllocationBase = const_cast<LPVOID>(lpAddress);
    lpBuffer->AllocationProtect = PAGE_EXECUTE_READWRITE;
    lpBuffer->RegionSize = 0x10000;
    lpBuffer->State = 0x1000; // MEM_COMMIT
    lpBuffer->Protect = PAGE_EXECUTE_READWRITE;
    lpBuffer->Type = 0x20000; // MEM_PRIVATE
    return sizeof(MEMORY_BASIC_INFORMATION);
}

inline void RtlCaptureContext(void* /*ContextRecord*/) noexcept {}
inline void* RtlLookupFunctionEntry(uint64_t /*ControlPc*/, uint64_t* ImageBase, void* /*HistoryTable*/) noexcept {
    if (ImageBase) *ImageBase = g_CurrentExecutableBase ? g_CurrentExecutableBase : 0x140000000ULL;
    return nullptr;
}
inline void* RtlVirtualUnwind(uint32_t /*HandlerType*/, uint64_t /*ImageBase*/, uint64_t /*ControlPc*/, void* /*FunctionEntry*/, void* /*ContextRecord*/, void** /*HandlerData*/, uint64_t* /*EstablisherFrame*/, void* /*ContextPointers*/) noexcept {
    return nullptr;
}
inline void RtlUnwindEx(void* /*TargetFrame*/, void* /*TargetIp*/, void* /*ExceptionRecord*/, void* /*ReturnValue*/, void* /*ContextRecord*/, void* /*HistoryTable*/) noexcept {}
inline void* RtlPcToFileHeader(void* /*PcValue*/, void** BaseOfImage) noexcept {
    uintptr_t base = g_CurrentExecutableBase ? g_CurrentExecutableBase : 0x140000000ULL;
    if (BaseOfImage) *BaseOfImage = reinterpret_cast<void*>(base);
    return reinterpret_cast<void*>(base);
}
inline void RaiseException(DWORD /*dwExceptionCode*/, DWORD /*dwExceptionFlags*/, DWORD /*nNumberOfArguments*/, const uint64_t* /*lpArguments*/) noexcept {}

// ============================================================================
// 18. Win32 Dynamic Subsystem Export Table Initializer
// ============================================================================

/**
 * @brief Registers all clean-room Win32 and NTDLL exports into the userland dynamic loader.
 */
inline void InitializeWin32SubsystemExports() {
    static bool s_Initialized = false;
    if (s_Initialized) return;
    s_Initialized = true;

    auto& ldr = ldr::DynamicLoader::get();

    // kernel32.dll exports
    ldr.registerExport("kernel32.dll", "GetProcessHeap", reinterpret_cast<void*>(GetProcessHeap));
    ldr.registerExport("kernel32.dll", "HeapAlloc", reinterpret_cast<void*>(HeapAlloc));
    ldr.registerExport("kernel32.dll", "HeapFree", reinterpret_cast<void*>(HeapFree));
    ldr.registerExport("kernel32.dll", "HeapReAlloc", reinterpret_cast<void*>(HeapReAlloc));
    ldr.registerExport("kernel32.dll", "HeapSize", reinterpret_cast<void*>(HeapSize));
    ldr.registerExport("kernel32.dll", "LocalAlloc", reinterpret_cast<void*>(LocalAlloc));
    ldr.registerExport("kernel32.dll", "LocalFree", reinterpret_cast<void*>(LocalFree));
    ldr.registerExport("kernel32.dll", "VirtualAlloc", reinterpret_cast<void*>(VirtualAlloc));
    ldr.registerExport("kernel32.dll", "VirtualFree", reinterpret_cast<void*>(VirtualFree));
    ldr.registerExport("kernel32.dll", "GetCurrentProcess", reinterpret_cast<void*>(GetCurrentProcess));
    ldr.registerExport("kernel32.dll", "GetCurrentProcessId", reinterpret_cast<void*>(GetCurrentProcessId));
    ldr.registerExport("kernel32.dll", "GetCurrentThread", reinterpret_cast<void*>(GetCurrentThread));
    ldr.registerExport("kernel32.dll", "GetCurrentThreadId", reinterpret_cast<void*>(GetCurrentThreadId));
    ldr.registerExport("kernel32.dll", "ExitProcess", reinterpret_cast<void*>(ExitProcess));
    ldr.registerExport("kernel32.dll", "CreateProcessW", reinterpret_cast<void*>(CreateProcessW));
    ldr.registerExport("kernel32.dll", "CreateProcessA", reinterpret_cast<void*>(CreateProcessA));
    ldr.registerExport("kernel32.dll", "AllocConsole", reinterpret_cast<void*>(AllocConsole));
    ldr.registerExport("kernel32.dll", "FreeConsole", reinterpret_cast<void*>(FreeConsole));
    ldr.registerExport("kernel32.dll", "SetConsoleTitleW", reinterpret_cast<void*>(SetConsoleTitleW));
    ldr.registerExport("kernel32.dll", "GetConsoleTitleW", reinterpret_cast<void*>(GetConsoleTitleW));
    ldr.registerExport("kernel32.dll", "GetStdHandle", reinterpret_cast<void*>(GetStdHandle));
    ldr.registerExport("kernel32.dll", "SetStdHandle", reinterpret_cast<void*>(SetStdHandle));
    ldr.registerExport("kernel32.dll", "WriteConsoleW", reinterpret_cast<void*>(WriteConsoleW));
    ldr.registerExport("kernel32.dll", "WriteConsoleA", reinterpret_cast<void*>(WriteConsoleA));
    ldr.registerExport("kernel32.dll", "GetConsoleMode", reinterpret_cast<void*>(GetConsoleMode));
    ldr.registerExport("kernel32.dll", "SetConsoleMode", reinterpret_cast<void*>(SetConsoleMode));
    ldr.registerExport("kernel32.dll", "GetConsoleScreenBufferInfo", reinterpret_cast<void*>(GetConsoleScreenBufferInfo));
    ldr.registerExport("kernel32.dll", "SetConsoleTextAttribute", reinterpret_cast<void*>(SetConsoleTextAttribute));
    ldr.registerExport("kernel32.dll", "SetConsoleCursorPosition", reinterpret_cast<void*>(SetConsoleCursorPosition));
    ldr.registerExport("kernel32.dll", "CreateFileW", reinterpret_cast<void*>(CreateFileW));
    ldr.registerExport("kernel32.dll", "ReadFile", reinterpret_cast<void*>(ReadFile));
    ldr.registerExport("kernel32.dll", "WriteFile", reinterpret_cast<void*>(WriteFile));
    ldr.registerExport("kernel32.dll", "CloseHandle", reinterpret_cast<void*>(CloseHandle));
    ldr.registerExport("kernel32.dll", "GetFileSize", reinterpret_cast<void*>(GetFileSize));
    ldr.registerExport("kernel32.dll", "GetFileSizeEx", reinterpret_cast<void*>(GetFileSizeEx));
    ldr.registerExport("kernel32.dll", "SetFilePointer", reinterpret_cast<void*>(SetFilePointer));
    ldr.registerExport("kernel32.dll", "SetFilePointerEx", reinterpret_cast<void*>(SetFilePointerEx));
    ldr.registerExport("kernel32.dll", "GetFileAttributesW", reinterpret_cast<void*>(GetFileAttributesW));
    ldr.registerExport("kernel32.dll", "GetFileAttributesA", reinterpret_cast<void*>(GetFileAttributesA));
    ldr.registerExport("kernel32.dll", "SetFileAttributesW", reinterpret_cast<void*>(SetFileAttributesW));
    ldr.registerExport("kernel32.dll", "DeleteFileW", reinterpret_cast<void*>(DeleteFileW));
    ldr.registerExport("kernel32.dll", "DeleteFileA", reinterpret_cast<void*>(DeleteFileA));
    ldr.registerExport("kernel32.dll", "CopyFileW", reinterpret_cast<void*>(CopyFileW));
    ldr.registerExport("kernel32.dll", "CopyFileA", reinterpret_cast<void*>(CopyFileA));
    ldr.registerExport("kernel32.dll", "MoveFileW", reinterpret_cast<void*>(MoveFileW));
    ldr.registerExport("kernel32.dll", "MoveFileA", reinterpret_cast<void*>(MoveFileA));
    ldr.registerExport("kernel32.dll", "MoveFileExW", reinterpret_cast<void*>(MoveFileExW));
    ldr.registerExport("kernel32.dll", "CreateDirectoryW", reinterpret_cast<void*>(CreateDirectoryW));
    ldr.registerExport("kernel32.dll", "CreateDirectoryA", reinterpret_cast<void*>(CreateDirectoryA));
    ldr.registerExport("kernel32.dll", "RemoveDirectoryW", reinterpret_cast<void*>(RemoveDirectoryW));
    ldr.registerExport("kernel32.dll", "RemoveDirectoryA", reinterpret_cast<void*>(RemoveDirectoryA));
    ldr.registerExport("kernel32.dll", "FindFirstFileW", reinterpret_cast<void*>(FindFirstFileW));
    ldr.registerExport("kernel32.dll", "FindNextFileW", reinterpret_cast<void*>(FindNextFileW));
    ldr.registerExport("kernel32.dll", "FindClose", reinterpret_cast<void*>(FindClose));
    ldr.registerExport("kernel32.dll", "CreateEventW", reinterpret_cast<void*>(CreateEventW));
    ldr.registerExport("kernel32.dll", "SetEvent", reinterpret_cast<void*>(SetEvent));
    ldr.registerExport("kernel32.dll", "ResetEvent", reinterpret_cast<void*>(ResetEvent));
    ldr.registerExport("kernel32.dll", "WaitForSingleObject", reinterpret_cast<void*>(WaitForSingleObject));
    ldr.registerExport("kernel32.dll", "WaitForMultipleObjects", reinterpret_cast<void*>(WaitForMultipleObjects));
    ldr.registerExport("kernel32.dll", "Sleep", reinterpret_cast<void*>(Sleep));
    ldr.registerExport("kernel32.dll", "GetTickCount64", reinterpret_cast<void*>(GetTickCount64));
    ldr.registerExport("kernel32.dll", "GetSystemInfo", reinterpret_cast<void*>(GetSystemInfo));
    ldr.registerExport("kernel32.dll", "LoadLibraryW", reinterpret_cast<void*>(LoadLibraryW));
    ldr.registerExport("kernel32.dll", "GetProcAddress", reinterpret_cast<void*>(GetProcAddress));
    ldr.registerExport("kernel32.dll", "FreeLibrary", reinterpret_cast<void*>(FreeLibrary));
    ldr.registerExport("kernel32.dll", "GetLastError", reinterpret_cast<void*>(GetLastError));
    ldr.registerExport("kernel32.dll", "SetLastError", reinterpret_cast<void*>(SetLastError));
    ldr.registerExport("kernel32.dll", "GetCommandLineA", reinterpret_cast<void*>(GetCommandLineA));
    ldr.registerExport("kernel32.dll", "GetCommandLineW", reinterpret_cast<void*>(GetCommandLineW));
    ldr.registerExport("kernel32.dll", "GetEnvironmentVariableA", reinterpret_cast<void*>(GetEnvironmentVariableA));
    ldr.registerExport("kernel32.dll", "GetEnvironmentVariableW", reinterpret_cast<void*>(GetEnvironmentVariableW));
    ldr.registerExport("kernel32.dll", "SetEnvironmentVariableA", reinterpret_cast<void*>(SetEnvironmentVariableA));
    ldr.registerExport("kernel32.dll", "SetEnvironmentVariableW", reinterpret_cast<void*>(SetEnvironmentVariableW));
    ldr.registerExport("kernel32.dll", "GetCurrentDirectoryA", reinterpret_cast<void*>(GetCurrentDirectoryA));
    ldr.registerExport("kernel32.dll", "GetCurrentDirectoryW", reinterpret_cast<void*>(GetCurrentDirectoryW));
    ldr.registerExport("kernel32.dll", "SetCurrentDirectoryA", reinterpret_cast<void*>(SetCurrentDirectoryA));
    ldr.registerExport("kernel32.dll", "SetCurrentDirectoryW", reinterpret_cast<void*>(SetCurrentDirectoryW));
    ldr.registerExport("kernel32.dll", "GetFullPathNameA", reinterpret_cast<void*>(GetFullPathNameA));
    ldr.registerExport("kernel32.dll", "GetFullPathNameW", reinterpret_cast<void*>(GetFullPathNameW));
    ldr.registerExport("kernel32.dll", "GetModuleFileNameA", reinterpret_cast<void*>(GetModuleFileNameA));
    ldr.registerExport("kernel32.dll", "GetModuleFileNameW", reinterpret_cast<void*>(GetModuleFileNameW));
    ldr.registerExport("kernel32.dll", "GetModuleHandleA", reinterpret_cast<void*>(GetModuleHandleA));
    ldr.registerExport("kernel32.dll", "GetModuleHandleW", reinterpret_cast<void*>(GetModuleHandleW));
    ldr.registerExport("kernel32.dll", "QueryPerformanceCounter", reinterpret_cast<void*>(QueryPerformanceCounter));
    ldr.registerExport("kernel32.dll", "QueryPerformanceFrequency", reinterpret_cast<void*>(QueryPerformanceFrequency));
    ldr.registerExport("kernel32.dll", "GetSystemTime", reinterpret_cast<void*>(GetSystemTime));
    ldr.registerExport("kernel32.dll", "GetLocalTime", reinterpret_cast<void*>(GetLocalTime));
    ldr.registerExport("kernel32.dll", "GetSystemTimeAsFileTime", reinterpret_cast<void*>(GetSystemTimeAsFileTime));
    ldr.registerExport("kernel32.dll", "CreateFileMappingW", reinterpret_cast<void*>(CreateFileMappingW));
    ldr.registerExport("kernel32.dll", "MapViewOfFile", reinterpret_cast<void*>(MapViewOfFile));
    ldr.registerExport("kernel32.dll", "UnmapViewOfFile", reinterpret_cast<void*>(UnmapViewOfFile));
    ldr.registerExport("kernel32.dll", "GetExitCodeProcess", reinterpret_cast<void*>(GetExitCodeProcess));
    ldr.registerExport("kernel32.dll", "TerminateProcess", reinterpret_cast<void*>(TerminateProcess));
    ldr.registerExport("kernel32.dll", "SwitchToThread", reinterpret_cast<void*>(SwitchToThread));

    // CRT startup & interop helpers
    ldr.registerExport("kernel32.dll", "InitializeSListHead", reinterpret_cast<void*>(InitializeSListHead));
    ldr.registerExport("kernel32.dll", "FlsAlloc", reinterpret_cast<void*>(FlsAlloc));
    ldr.registerExport("kernel32.dll", "FlsGetValue", reinterpret_cast<void*>(FlsGetValue));
    ldr.registerExport("kernel32.dll", "FlsSetValue", reinterpret_cast<void*>(FlsSetValue));
    ldr.registerExport("kernel32.dll", "FlsFree", reinterpret_cast<void*>(FlsFree));
    ldr.registerExport("kernel32.dll", "InitializeCriticalSection", reinterpret_cast<void*>(InitializeCriticalSection));
    ldr.registerExport("kernel32.dll", "InitializeCriticalSectionEx", reinterpret_cast<void*>(InitializeCriticalSectionEx));
    ldr.registerExport("kernel32.dll", "EnterCriticalSection", reinterpret_cast<void*>(EnterCriticalSection));
    ldr.registerExport("kernel32.dll", "LeaveCriticalSection", reinterpret_cast<void*>(LeaveCriticalSection));
    ldr.registerExport("kernel32.dll", "DeleteCriticalSection", reinterpret_cast<void*>(DeleteCriticalSection));
    ldr.registerExport("kernel32.dll", "EncodePointer", reinterpret_cast<void*>(EncodePointer));
    ldr.registerExport("kernel32.dll", "DecodePointer", reinterpret_cast<void*>(DecodePointer));
    ldr.registerExport("kernel32.dll", "GetStartupInfoW", reinterpret_cast<void*>(GetStartupInfoW));
    ldr.registerExport("kernel32.dll", "GetFileType", reinterpret_cast<void*>(GetFileType));
    ldr.registerExport("kernel32.dll", "IsProcessorFeaturePresent", reinterpret_cast<void*>(IsProcessorFeaturePresent));
    ldr.registerExport("kernel32.dll", "IsDebuggerPresent", reinterpret_cast<void*>(IsDebuggerPresent));
    ldr.registerExport("kernel32.dll", "SetUnhandledExceptionFilter", reinterpret_cast<void*>(SetUnhandledExceptionFilter));
    ldr.registerExport("kernel32.dll", "UnhandledExceptionFilter", reinterpret_cast<void*>(UnhandledExceptionFilter));
    ldr.registerExport("kernel32.dll", "MultiByteToWideChar", reinterpret_cast<void*>(MultiByteToWideChar));
    ldr.registerExport("kernel32.dll", "WideCharToMultiByte", reinterpret_cast<void*>(WideCharToMultiByte));
    ldr.registerExport("kernel32.dll", "GetACP", reinterpret_cast<void*>(GetACP));
    ldr.registerExport("kernel32.dll", "GetOEMCP", reinterpret_cast<void*>(GetOEMCP));
    ldr.registerExport("kernel32.dll", "IsValidCodePage", reinterpret_cast<void*>(IsValidCodePage));
    ldr.registerExport("kernel32.dll", "GetCPInfo", reinterpret_cast<void*>(GetCPInfo));
    ldr.registerExport("kernel32.dll", "CompareStringW", reinterpret_cast<void*>(CompareStringW));
    ldr.registerExport("kernel32.dll", "LCMapStringW", reinterpret_cast<void*>(LCMapStringW));
    ldr.registerExport("kernel32.dll", "FindFirstFileExW", reinterpret_cast<void*>(FindFirstFileExW));
    ldr.registerExport("kernel32.dll", "FlushFileBuffers", reinterpret_cast<void*>(FlushFileBuffers));
    ldr.registerExport("kernel32.dll", "GetEnvironmentStringsW", reinterpret_cast<void*>(GetEnvironmentStringsW));
    ldr.registerExport("kernel32.dll", "FreeEnvironmentStringsW", reinterpret_cast<void*>(FreeEnvironmentStringsW));
    ldr.registerExport("kernel32.dll", "GetStringTypeW", reinterpret_cast<void*>(GetStringTypeW));
    ldr.registerExport("kernel32.dll", "VirtualProtect", reinterpret_cast<void*>(VirtualProtect));
    ldr.registerExport("kernel32.dll", "VirtualQuery", reinterpret_cast<void*>(VirtualQuery));
    ldr.registerExport("kernel32.dll", "TlsAlloc", reinterpret_cast<void*>(TlsAlloc));
    ldr.registerExport("kernel32.dll", "TlsGetValue", reinterpret_cast<void*>(TlsGetValue));
    ldr.registerExport("kernel32.dll", "TlsSetValue", reinterpret_cast<void*>(TlsSetValue));
    ldr.registerExport("kernel32.dll", "TlsFree", reinterpret_cast<void*>(TlsFree));
    ldr.registerExport("kernel32.dll", "RtlCaptureContext", reinterpret_cast<void*>(RtlCaptureContext));
    ldr.registerExport("kernel32.dll", "RtlLookupFunctionEntry", reinterpret_cast<void*>(RtlLookupFunctionEntry));
    ldr.registerExport("kernel32.dll", "RtlVirtualUnwind", reinterpret_cast<void*>(RtlVirtualUnwind));
    ldr.registerExport("kernel32.dll", "RtlUnwindEx", reinterpret_cast<void*>(RtlUnwindEx));
    ldr.registerExport("kernel32.dll", "RtlPcToFileHeader", reinterpret_cast<void*>(RtlPcToFileHeader));
    ldr.registerExport("kernel32.dll", "RaiseException", reinterpret_cast<void*>(RaiseException));
    ldr.registerExport("kernel32.dll", "LoadLibraryExW", reinterpret_cast<void*>(LoadLibraryExW));
    ldr.registerExport("kernel32.dll", "GetModuleHandleExW", reinterpret_cast<void*>(GetModuleHandleExW));
    ldr.registerExport("kernel32.dll", "GetConsoleOutputCP", reinterpret_cast<void*>(GetConsoleOutputCP));

    // Named Pipes & Mailslots IPC exports
    ldr.registerExport("kernel32.dll", "CreateNamedPipeW", reinterpret_cast<void*>(CreateNamedPipeW));
    ldr.registerExport("kernel32.dll", "ConnectNamedPipe", reinterpret_cast<void*>(ConnectNamedPipe));
    ldr.registerExport("kernel32.dll", "DisconnectNamedPipe", reinterpret_cast<void*>(DisconnectNamedPipe));
    ldr.registerExport("kernel32.dll", "WaitNamedPipeW", reinterpret_cast<void*>(WaitNamedPipeW));
    ldr.registerExport("kernel32.dll", "PeekNamedPipe", reinterpret_cast<void*>(PeekNamedPipe));
    ldr.registerExport("kernel32.dll", "TransactNamedPipe", reinterpret_cast<void*>(TransactNamedPipe));
    ldr.registerExport("kernel32.dll", "GetNamedPipeInfo", reinterpret_cast<void*>(GetNamedPipeInfo));
    ldr.registerExport("kernel32.dll", "GetNamedPipeHandleStateW", reinterpret_cast<void*>(GetNamedPipeHandleStateW));
    ldr.registerExport("kernel32.dll", "SetNamedPipeHandleState", reinterpret_cast<void*>(SetNamedPipeHandleState));
    ldr.registerExport("kernel32.dll", "CreateMailslotW", reinterpret_cast<void*>(CreateMailslotW));
    ldr.registerExport("kernel32.dll", "GetMailslotInfo", reinterpret_cast<void*>(GetMailslotInfo));
    ldr.registerExport("kernel32.dll", "SetMailslotInfo", reinterpret_cast<void*>(SetMailslotInfo));

    // ntdll.dll exports
    ldr.registerExport("ntdll.dll", "RtlAllocateHeap", reinterpret_cast<void*>(ntdll::RtlAllocateHeap));
    ldr.registerExport("ntdll.dll", "RtlFreeHeap", reinterpret_cast<void*>(ntdll::RtlFreeHeap));
    ldr.registerExport("ntdll.dll", "RtlCreateHeap", reinterpret_cast<void*>(ntdll::RtlCreateHeap));
    ldr.registerExport("ntdll.dll", "RtlDestroyHeap", reinterpret_cast<void*>(ntdll::RtlDestroyHeap));
    ldr.registerExport("ntdll.dll", "RtlSizeHeap", reinterpret_cast<void*>(ntdll::RtlSizeHeap));
    ldr.registerExport("ntdll.dll", "RtlSetLastWin32Error", reinterpret_cast<void*>(ntdll::RtlSetLastWin32Error));
    ldr.registerExport("ntdll.dll", "RtlGetLastWin32Error", reinterpret_cast<void*>(ntdll::RtlGetLastWin32Error));
    ldr.registerExport("ntdll.dll", "RtlNtStatusToDosError", reinterpret_cast<void*>(ntdll::RtlNtStatusToDosError));
    ldr.registerExport("ntdll.dll", "NtAllocateVirtualMemory", reinterpret_cast<void*>(ntdll::NtAllocateVirtualMemory));
    ldr.registerExport("ntdll.dll", "NtFreeVirtualMemory", reinterpret_cast<void*>(ntdll::NtFreeVirtualMemory));
    ldr.registerExport("ntdll.dll", "NtWriteFile", reinterpret_cast<void*>(ntdll::NtWriteFile));
    ldr.registerExport("ntdll.dll", "NtReadFile", reinterpret_cast<void*>(ntdll::NtReadFile));
    ldr.registerExport("ntdll.dll", "NtClose", reinterpret_cast<void*>(ntdll::NtClose));
    ldr.registerExport("ntdll.dll", "NtWaitForSingleObject", reinterpret_cast<void*>(ntdll::NtWaitForSingleObject));
    ldr.registerExport("ntdll.dll", "NtCreateSection", reinterpret_cast<void*>(ntdll::NtCreateSection));
    ldr.registerExport("ntdll.dll", "NtMapViewOfSection", reinterpret_cast<void*>(ntdll::NtMapViewOfSection));
    ldr.registerExport("ntdll.dll", "NtUnmapViewOfSection", reinterpret_cast<void*>(ntdll::NtUnmapViewOfSection));
    ldr.registerExport("ntdll.dll", "NtQueryInformationFile", reinterpret_cast<void*>(ntdll::NtQueryInformationFile));
    ldr.registerExport("ntdll.dll", "NtSetInformationFile", reinterpret_cast<void*>(ntdll::NtSetInformationFile));
    ldr.registerExport("ntdll.dll", "NtQueryDirectoryFile", reinterpret_cast<void*>(ntdll::NtQueryDirectoryFile));
    ldr.registerExport("ntdll.dll", "NtQueryPerformanceCounter", reinterpret_cast<void*>(ntdll::NtQueryPerformanceCounter));
    ldr.registerExport("ntdll.dll", "NtYieldExecution", reinterpret_cast<void*>(ntdll::NtYieldExecution));
    ldr.registerExport("ntdll.dll", "NtQueryInformationProcess", reinterpret_cast<void*>(ntdll::NtQueryInformationProcess));
    ldr.registerExport("ntdll.dll", "NtCreateNamedPipeFile", reinterpret_cast<void*>(ntdll::NtCreateNamedPipeFile));
    ldr.registerExport("ntdll.dll", "NtCreateMailslotFile", reinterpret_cast<void*>(ntdll::NtCreateMailslotFile));
}


} // namespace micant::win32

namespace micant {
namespace kernel32 = win32;
}
