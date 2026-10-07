#pragma once

/**
 * @file wow64.hpp
 * @brief Clean-Room Windows-on-Windows 64-Bit Subsystem (WoW64).
 *
 * Implements 32-bit application compatibility on 64-bit MicaNT, including:
 * - 32-bit PEB (PEB32) and TEB (TEB32) within 4GB virtual address space.
 * - Heaven's Gate segment selector transitions (0x23 compatibility mode <-> 0x33 long mode).
 * - 32-to-64 bit pointer widening and system call thunking (wow64cpu / wow64).
 * - Transparent File System (SysWOW64) and Registry (WOW6432Node) redirection.
 *
 * References: Microsoft win32metadata & Microsoft Learn Public WoW64 Architecture.
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <algorithm>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "syscalls.hpp"
#include "dispatcher.hpp"

namespace micant::wow64 {

// ============================================================================
// 1. 32-Bit Fundamental Types & Structures
// ============================================================================

using PVOID32  = uint32_t;
using HANDLE32 = uint32_t;
using SIZE_T32 = uint32_t;
using BOOL32   = int32_t;
using BOOL     = int32_t;

struct ClientId32 {
    uint32_t uniqueProcess{0};
    uint32_t uniqueThread{0};
};

struct UnicodeString32 {
    uint16_t length{0};
    uint16_t maximumLength{0};
    PVOID32  buffer{0};
};

struct IoStatusBlock32 {
    union {
        NtStatus status;
        PVOID32  pointer;
    };
    uint32_t information{0};
};

struct LargeInteger32 {
    uint32_t lowPart{0};
    int32_t  highPart{0};

    [[nodiscard]] int64_t toInt64() const noexcept {
        return (static_cast<int64_t>(highPart) << 32) | lowPart;
    }

    static LargeInteger32 fromInt64(int64_t val) noexcept {
        return LargeInteger32{
            .lowPart = static_cast<uint32_t>(val & 0xFFFFFFFF),
            .highPart = static_cast<int32_t>((val >> 32) & 0xFFFFFFFF)
        };
    }
};

// ============================================================================
// 2. 32-Bit Process & Thread Environment Blocks (PEB32 & TEB32)
// ============================================================================

struct ListEntry32 {
    uint32_t flink{0};
    uint32_t blink{0};
};

struct PebLdrData32 {
    uint32_t length{sizeof(PebLdrData32)};
    uint8_t  initialized{1};
    uint32_t ssHandle{0};
    ListEntry32 inLoadOrderModuleList{};
    ListEntry32 inMemoryOrderModuleList{};
    ListEntry32 inInitializationOrderModuleList{};
};

struct ProcessEnvironmentBlock32 {
    uint8_t  inheritedAddressSpace{0};
    uint8_t  readImageFileExecOptions{0};
    uint8_t  beingDebugged{0};
    uint8_t  spareBool{0};
    HANDLE32 mutant{0};
    PVOID32  imageBaseAddress{0x00400000};
    PVOID32  ldr{0};
    PVOID32  processParameters{0};
    PVOID32  subSystemData{0};
    PVOID32  processHeap{0};
    PVOID32  fastPebLock{0};
    PVOID32  session{0};
    uint32_t osMajorVersion{10};
    uint32_t osMinorVersion{0};
    uint16_t osBuildNumber{26100};
    uint16_t osCSDVersion{0};
    uint32_t osPlatformId{2}; // VER_PLATFORM_WIN32_NT
    uint32_t numberOfProcessors{4};
    uint32_t ntGlobalFlag{0};
};

struct ThreadEnvironmentBlock32 {
    uint32_t exceptionList{0};
    uint32_t stackBase{0};
    uint32_t stackLimit{0};
    uint32_t subSystemTib{0};
    uint32_t fiberData{0};
    uint32_t arbitraryUserPointer{0};
    uint32_t self{0}; // Points to this TEB32
    uint32_t environmentPointer{0};
    ClientId32 clientId{};
    uint32_t activeRpcHandle{0};
    uint32_t threadLocalStoragePointer{0};
    uint32_t processEnvironmentBlock{0}; // Points to PEB32
    uint32_t lastErrorValue{0};
    uint32_t countOfOwnedCriticalSections{0};
    uint32_t csrClientThread{0};
    uint32_t win32ThreadInfo{0};
    uint32_t currentLocale{0x0409}; // en-US
    uint32_t fpxsaveArea{0};
    uint32_t wow64Reserved{0};      // Points to 64-bit TEB fast thunk channel
};

// Thread-local 32-bit TEB and PEB pointers
inline thread_local ThreadEnvironmentBlock32* g_CurrentTeb32 = nullptr;
inline thread_local ProcessEnvironmentBlock32* g_CurrentPeb32 = nullptr;

[[nodiscard]] inline ThreadEnvironmentBlock32* RtlGetCurrentTeb32() noexcept {
    return g_CurrentTeb32;
}

[[nodiscard]] inline ProcessEnvironmentBlock32* RtlGetCurrentPeb32() noexcept {
    if (g_CurrentPeb32) return g_CurrentPeb32;
    if (!g_CurrentTeb32 || g_CurrentTeb32->processEnvironmentBlock == 0) return nullptr;
    return reinterpret_cast<ProcessEnvironmentBlock32*>(static_cast<uintptr_t>(g_CurrentTeb32->processEnvironmentBlock));
}

inline void RtlSetCurrentTeb32(ThreadEnvironmentBlock32* teb32, ProcessEnvironmentBlock32* peb32 = nullptr) noexcept {
    g_CurrentTeb32 = teb32;
    g_CurrentPeb32 = peb32;
}

inline void RtlSetCurrentPeb32(ProcessEnvironmentBlock32* peb32) noexcept {
    g_CurrentPeb32 = peb32;
}

// ============================================================================
// 3. Heaven's Gate Architecture & Segment Mode Switcher
// ============================================================================

inline constexpr uint16_t WOW64_CS_32BIT = 0x23; // Compatibility Mode Code Segment
inline constexpr uint16_t WOW64_CS_64BIT = 0x33; // Long Mode (64-bit) Code Segment
inline constexpr uint16_t WOW64_SS_32BIT = 0x2B; // 32-Bit Stack Segment

struct Wow64Context32 {
    uint32_t contextFlags{0x00010007}; // CONTEXT_FULL
    uint32_t dr0{0}, dr1{0}, dr2{0}, dr3{0}, dr6{0}, dr7{0};

    // Segment Registers
    uint32_t segGs{0};
    uint32_t segFs{0x53}; // Standard x86 TEB selector
    uint32_t segEs{0x2B};
    uint32_t segDs{0x2B};

    // General Purpose Registers
    uint32_t edi{0};
    uint32_t esi{0};
    uint32_t ebx{0};
    uint32_t edx{0};
    uint32_t ecx{0};
    uint32_t eax{0};

    // Stack & Execution Control
    uint32_t ebp{0};
    uint32_t eip{0};
    uint32_t segCs{WOW64_CS_32BIT};
    uint32_t eflags{0x00000202};
    uint32_t esp{0};
    uint32_t segSs{WOW64_SS_32BIT};
};

/**
 * @brief Clean-Room Heaven's Gate Mode Transition Simulator.
 * Models the far call / far jump selector switch between 32-bit x86 and 64-bit AMD64.
 */
class HeavensGate {
public:
    /**
     * @brief Transitions execution context from 32-bit compatibility mode to 64-bit long mode.
     */
    static bool enter64BitMode(Wow64Context32& ctx32, uint64_t& outRip64, uint64_t targetRip64) noexcept {
        if (ctx32.segCs != WOW64_CS_32BIT) {
            return false; // Already in 64-bit mode or invalid state
        }
        ctx32.segCs = WOW64_CS_64BIT;
        outRip64 = targetRip64;
        return true;
    }

    /**
     * @brief Transitions execution context from 64-bit long mode back to 32-bit compatibility mode.
     */
    static bool exitTo32BitMode(uint64_t rip64, Wow64Context32& ctx32, uint32_t returnEip32) noexcept {
        (void)rip64;
        if (ctx32.segCs != WOW64_CS_64BIT) {
            return false;
        }
        ctx32.segCs = WOW64_CS_32BIT;
        ctx32.eip = returnEip32;
        return true;
    }
};

// ============================================================================
// 4. File System & Registry Redirection (SysWOW64 & WOW6432Node)
// ============================================================================

/**
 * @brief WoW64 File System and Registry Virtualization Manager.
 */
class Wow64FsRedirection {
private:
    inline static thread_local bool t_redirectionDisabled{false};

public:
    /**
     * @brief Disables file system redirection for the calling thread.
     */
    static BOOL disable(PVOID32* oldState) noexcept {
        if (oldState) *oldState = t_redirectionDisabled ? 1 : 0;
        t_redirectionDisabled = true;
        return 1;
    }

    /**
     * @brief Restores file system redirection for the calling thread.
     */
    static BOOL revert(PVOID32 oldState) noexcept {
        t_redirectionDisabled = (oldState != 0);
        return 1;
    }

    [[nodiscard]] static bool isRedirectionDisabled() noexcept {
        return t_redirectionDisabled;
    }

    /**
     * @brief Translates file paths, redirecting System32 -> SysWOW64 for 32-bit processes.
     */
    [[nodiscard]] static std::wstring translatePath(std::wstring_view inputPath) {
        if (t_redirectionDisabled) {
            return std::wstring(inputPath);
        }

        std::wstring path(inputPath);

        // Check for System32 exemption patterns
        if (path.find(L"\\System32\\drivers\\etc") != std::wstring::npos ||
            path.find(L"\\System32\\spool") != std::wstring::npos ||
            path.find(L"\\System32\\catroot") != std::wstring::npos) {
            return path;
        }

        // Standard System32 -> SysWOW64 substitution
        constexpr std::wstring_view sys32 = L"\\Windows\\System32";
        constexpr std::wstring_view syswow64 = L"\\Windows\\SysWOW64";

        auto pos = path.find(sys32);
        if (pos != std::wstring::npos) {
            path.replace(pos, sys32.length(), syswow64);
        }

        return path;
    }

    /**
     * @brief Translates registry paths, redirecting HKLM\Software -> WOW6432Node.
     */
    [[nodiscard]] static std::wstring translateRegistryKey(std::wstring_view inputKey) {
        std::wstring key(inputKey);
        constexpr std::wstring_view sw = L"\\Registry\\Machine\\Software";
        constexpr std::wstring_view sw32 = L"\\Registry\\Machine\\Software\\WOW6432Node";

        if (key.starts_with(sw) && !key.starts_with(sw32)) {
            key.replace(0, sw.length(), sw32);
        }

        return key;
    }
};

// ============================================================================
// 5. 32-to-64 Bit System Call Thunk Engine (wow64cpu.dll & wow64.dll)
// ============================================================================

/**
 * @brief Clean-Room WoW64 System Call Thunking Engine.
 * Widens 32-bit pointers and marshals data structures to invoke the 64-bit kernel dispatch table.
 */
class Wow64ThunkDispatcher {
public:
    static Wow64ThunkDispatcher& get() {
        static Wow64ThunkDispatcher instance;
        return instance;
    }

    /**
     * @brief Thunk for NtAllocateVirtualMemory (32-bit -> 64-bit).
     */
    NtStatus thunkNtAllocateVirtualMemory(
        HANDLE32 processHandle,
        PVOID32* baseAddress32,
        uint32_t zeroBits,
        SIZE_T32* regionSize32,
        uint32_t allocationType,
        uint32_t protect
    ) {
        if (!baseAddress32 || !regionSize32) {
            return NtStatus::InvalidParameter;
        }

        // 1. Widen 32-bit parameters to 64-bit
        uintptr_t base64 = *baseAddress32;
        size_t size64 = *regionSize32;

        // In WoW64, if baseAddress is 0, constrain dynamic allocation to the 32-bit address space (< 4GB)
        static uintptr_t s_Wow64NextFreeAddress = 0x00500000;
        if (base64 == 0) {
            base64 = s_Wow64NextFreeAddress;
            s_Wow64NextFreeAddress += ((size64 + 0xFFFF) & ~0xFFFF); // 64KB granularity
        }

        // 2. Invoke 64-bit KiSystemCall64 dispatcher
        uint64_t stack[2] = { allocationType, protect };
        sys::SyscallFrame frame{
            .ssn = sys::SSN_NtAllocateVirtualMemory,
            .arg1 = static_cast<uint64_t>(processHandle),
            .arg2 = reinterpret_cast<uint64_t>(&base64),
            .arg3 = zeroBits,
            .arg4 = reinterpret_cast<uint64_t>(&size64),
            .stackArgs = stack,
            .stackArgCount = 2
        };

        NtStatus status = sys::SyscallDispatcher::get().dispatch(frame);

        // 3. Downcast results back to 32-bit if allocation succeeded
        if (NT_SUCCESS(status)) {
            // Check that allocated base fits in 32-bit address space
            if (base64 > 0xFFFFFFFFULL) {
                return NtStatus::NoMemory; // Outside 32-bit user range
            }
            *baseAddress32 = static_cast<PVOID32>(base64);
            *regionSize32 = static_cast<SIZE_T32>(size64);
        }

        return status;
    }

    /**
     * @brief Thunk for NtFreeVirtualMemory (32-bit -> 64-bit).
     */
    NtStatus thunkNtFreeVirtualMemory(
        HANDLE32 processHandle,
        PVOID32* baseAddress32,
        SIZE_T32* regionSize32,
        uint32_t freeType
    ) {
        if (!baseAddress32) return NtStatus::InvalidParameter;

        uintptr_t base64 = *baseAddress32;
        size_t size64 = regionSize32 ? *regionSize32 : 0;

        sys::SyscallFrame frame{
            .ssn = sys::SSN_NtFreeVirtualMemory,
            .arg1 = static_cast<uint64_t>(processHandle),
            .arg2 = reinterpret_cast<uint64_t>(&base64),
            .arg3 = reinterpret_cast<uint64_t>(&size64),
            .arg4 = freeType
        };

        NtStatus status = sys::SyscallDispatcher::get().dispatch(frame);
        if (NT_SUCCESS(status) && regionSize32) {
            *regionSize32 = static_cast<SIZE_T32>(size64);
        }
        return status;
    }

    /**
     * @brief Thunk for NtWriteFile (32-bit -> 64-bit).
     */
    NtStatus thunkNtWriteFile(
        HANDLE32 fileHandle,
        HANDLE32 event,
        PVOID32 /*apcRoutine*/,
        PVOID32 /*apcContext*/,
        IoStatusBlock32* iosb32,
        const void* buffer,
        uint32_t length,
        LargeInteger32* byteOffset32,
        PVOID32 /*key*/
    ) {
        if (!buffer || !iosb32) return NtStatus::InvalidParameter;

        IoStatusBlock iosb64{};
        LargeInteger byteOffset64{};
        LargeInteger* pOffset64 = nullptr;
        if (byteOffset32) {
            byteOffset64.quadPart = byteOffset32->toInt64();
            pOffset64 = &byteOffset64;
        }

        uint64_t stack[5] = {
            reinterpret_cast<uint64_t>(&iosb64),
            reinterpret_cast<uint64_t>(buffer),
            length,
            reinterpret_cast<uint64_t>(pOffset64),
            0
        };

        sys::SyscallFrame frame{
            .ssn = sys::SSN_NtWriteFile,
            .arg1 = static_cast<uint64_t>(fileHandle),
            .arg2 = static_cast<uint64_t>(event),
            .arg3 = 0,
            .arg4 = 0,
            .stackArgs = stack,
            .stackArgCount = 5
        };

        NtStatus status = sys::SyscallDispatcher::get().dispatch(frame);

        // Copy back to 32-bit status block
        iosb32->status = iosb64.status;
        iosb32->information = static_cast<uint32_t>(iosb64.information);

        return status;
    }

    /**
     * @brief Thunk for NtReadFile (32-bit -> 64-bit).
     */
    NtStatus thunkNtReadFile(
        HANDLE32 fileHandle,
        HANDLE32 event,
        PVOID32 /*apcRoutine*/,
        PVOID32 /*apcContext*/,
        IoStatusBlock32* iosb32,
        void* buffer,
        uint32_t length,
        LargeInteger32* byteOffset32,
        PVOID32 /*key*/
    ) {
        if (!buffer || !iosb32) return NtStatus::InvalidParameter;

        IoStatusBlock iosb64{};
        LargeInteger byteOffset64{};
        LargeInteger* pOffset64 = nullptr;
        if (byteOffset32) {
            byteOffset64.quadPart = byteOffset32->toInt64();
            pOffset64 = &byteOffset64;
        }

        uint64_t stack[5] = {
            reinterpret_cast<uint64_t>(&iosb64),
            reinterpret_cast<uint64_t>(buffer),
            length,
            reinterpret_cast<uint64_t>(pOffset64),
            0
        };

        sys::SyscallFrame frame{
            .ssn = sys::SSN_NtReadFile,
            .arg1 = static_cast<uint64_t>(fileHandle),
            .arg2 = static_cast<uint64_t>(event),
            .arg3 = 0,
            .arg4 = 0,
            .stackArgs = stack,
            .stackArgCount = 5
        };

        NtStatus status = sys::SyscallDispatcher::get().dispatch(frame);

        iosb32->status = iosb64.status;
        iosb32->information = static_cast<uint32_t>(iosb64.information);

        return status;
    }

    /**
     * @brief Thunk for NtClose (32-bit -> 64-bit).
     */
    NtStatus thunkNtClose(HANDLE32 handle) {
        sys::SyscallFrame frame{
            .ssn = sys::SSN_NtClose,
            .arg1 = static_cast<uint64_t>(handle)
        };
        return sys::SyscallDispatcher::get().dispatch(frame);
    }

    /**
     * @brief Thunk for NtWaitForSingleObject (32-bit -> 64-bit).
     */
    NtStatus thunkNtWaitForSingleObject(HANDLE32 handle, bool alertable, const LargeInteger32* timeout32) {
        LargeInteger timeout64{};
        LargeInteger* pTimeout64 = nullptr;
        if (timeout32) {
            timeout64.quadPart = timeout32->toInt64();
            pTimeout64 = &timeout64;
        }

        sys::SyscallFrame frame{
            .ssn = sys::SSN_NtWaitForSingleObject,
            .arg1 = static_cast<uint64_t>(handle),
            .arg2 = alertable ? 1ULL : 0ULL,
            .arg3 = reinterpret_cast<uint64_t>(pTimeout64)
        };
        return sys::SyscallDispatcher::get().dispatch(frame);
    }
};

} // namespace micant::wow64
