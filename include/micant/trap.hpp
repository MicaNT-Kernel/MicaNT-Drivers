#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <iostream>
#include <iomanip>
#include <functional>
#include <atomic>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ke.hpp"
#include "ps.hpp"
#include "mm.hpp"

namespace micant::ke {

// Standard NT BugCheck Stop Codes (BSOD codes)
inline constexpr uint32_t IRQL_NOT_LESS_OR_EQUAL            = 0x0000000A;
inline constexpr uint32_t KMODE_EXCEPTION_NOT_HANDLED       = 0x0000001E;
inline constexpr uint32_t PAGE_FAULT_IN_NONPAGED_AREA       = 0x00000050;
inline constexpr uint32_t SYSTEM_SERVICE_EXCEPTION          = 0x0000003B;
inline constexpr uint32_t CRITICAL_PROCESS_DIED             = 0x000000EF;
inline constexpr uint32_t UNEXPECTED_KERNEL_MODE_TRAP       = 0x0000007F;

// Standard Exception Codes
inline constexpr uint32_t EXCEPTION_ACCESS_VIOLATION        = 0xC0000005;
inline constexpr uint32_t EXCEPTION_DATATYPE_MISALIGNMENT   = 0x80000002;
inline constexpr uint32_t EXCEPTION_BREAKPOINT              = 0x80000003;
inline constexpr uint32_t EXCEPTION_SINGLE_STEP             = 0x80000004;
inline constexpr uint32_t EXCEPTION_ILLEGAL_INSTRUCTION     = 0xC000001D;
inline constexpr uint32_t EXCEPTION_INT_DIVIDE_BY_ZERO      = 0xC0000094;

/**
 * @brief Standard NT Exception Record.
 */
struct ExceptionRecord {
    uint32_t exceptionCode{0};
    uint32_t exceptionFlags{0}; // 0 = Continuable, 1 = Noncontinuable (EXCEPTION_NONCONTINUABLE)
    ExceptionRecord* exceptionRecord{nullptr};
    void* exceptionAddress{nullptr};
    uint32_t numberParameters{0};
    uintptr_t exceptionInformation[15]{0};
};

/**
 * @brief Crash Dump Header & Crash State.
 */
struct BugCheckFrame {
    uint32_t bugCheckCode{0};
    uintptr_t param1{0};
    uintptr_t param2{0};
    uintptr_t param3{0};
    uintptr_t param4{0};
    ps::ContextFrame context{};
    bool dumpGenerated{false};
};

/**
 * @brief Kernel Trap and Exception Engine.
 */
class TrapEngine {
public:
    static TrapEngine& get() {
        static TrapEngine instance;
        return instance;
    }

    /**
     * @brief Resolves a Page Fault (#PF Vector 14) via Demand Paging or Copy-On-Write.
     */
    [[nodiscard]] NtStatus handlePageFault(
        ps::EProcess& process,
        uintptr_t faultAddress,
        bool isWrite,
        bool isExecute
    ) {
        auto& addrSpace = process.getAddressSpace();
        auto* vad = addrSpace.findVad(faultAddress);

        // 1. If address is not covered by any allocated VAD region -> STATUS_ACCESS_VIOLATION
        if (!vad) {
            return NtStatus::AccessViolation;
        }

        // 2. Validate against protection flags
        if (isExecute && !(vad->protection & (mm::PAGE_EXECUTE | mm::PAGE_EXECUTE_READ | mm::PAGE_EXECUTE_READWRITE))) {
            return NtStatus::AccessViolation;
        }

        if (isWrite && !(vad->protection & (mm::PAGE_READWRITE | mm::PAGE_EXECUTE_READWRITE | mm::PAGE_WRITECOPY))) {
            return NtStatus::AccessViolation;
        }

        // 3. Demand Paging: Page committed on demand
        if (!vad->committed) {
            vad->committed = true;
        }

        // 4. Copy-on-Write resolution (PAGE_WRITECOPY)
        if (isWrite && (vad->protection & mm::PAGE_WRITECOPY)) {
            vad->protection = mm::PAGE_READWRITE;
            cowFaultsResolved_++;
        }

        pageFaultsResolved_++;
        return NtStatus::Success;
    }

    /**
     * @brief Structured Exception Dispatcher (KiDispatchException).
     * Dispatches first-chance, then frame-based SEH filters, then second-chance.
     */
    NtStatus dispatchException(
        ExceptionRecord& record,
        ps::ContextFrame& context,
        ps::EThread& thread,
        bool firstChance
    ) {
        // If debugger attached / first chance callback present
        if (firstChance && debuggerHandler_) {
            bool handled = debuggerHandler_(record, context);
            if (handled) return NtStatus::Success;
        }

        // Userland Frame-based SEH evaluation
        if (context.cs == 0x33) { // Ring 3 User Mode
            if (firstChance) {
                // If user handler installed
                if (userSehHandler_) {
                    bool handled = userSehHandler_(record, context);
                    if (handled) return NtStatus::Success;
                }
                // Unhandled in first-chance -> proceed to second-chance
                return NtStatus::Unsuccessful;
            } else {
                // Second-chance unhandled in user mode: Terminate Process
                if (thread.getOwnerProcess()) {
                    thread.getOwnerProcess()->terminate(static_cast<NtStatus>(record.exceptionCode));
                }
                return NtStatus::ProcessIsTerminating;
            }
        } else {
            // Kernel Mode (Ring 0): Unhandled exception in kernel mode triggers KeBugCheckEx!
            keBugCheckEx(
                KMODE_EXCEPTION_NOT_HANDLED,
                record.exceptionCode,
                reinterpret_cast<uintptr_t>(record.exceptionAddress),
                context.rip,
                0
            );
            return NtStatus::Unsuccessful;
        }
    }

    /**
     * @brief Kernel Bug Check (KeBugCheckEx).
     * Halts system or triggers crash minidump.
     */
    void keBugCheckEx(
        uint32_t bugCheckCode,
        uintptr_t p1,
        uintptr_t p2,
        uintptr_t p3,
        uintptr_t p4 = 0
    ) {
        lastBugCheck_.bugCheckCode = bugCheckCode;
        lastBugCheck_.param1 = p1;
        lastBugCheck_.param2 = p2;
        lastBugCheck_.param3 = p3;
        lastBugCheck_.param4 = p4;
        lastBugCheck_.dumpGenerated = true;

        std::cerr << "\n*** STOP: 0x" << std::hex << std::setw(8) << std::setfill('0') << bugCheckCode 
                  << " (0x" << p1 << ", 0x" << p2 << ", 0x" << p3 << ", 0x" << p4 << ")\n"
                  << "    Crash dump recorded in memory minidump buffer.\n" << std::dec;
    }

    void setDebuggerHandler(std::function<bool(const ExceptionRecord&, ps::ContextFrame&)> handler) {
        debuggerHandler_ = std::move(handler);
    }

    void setUserSehHandler(std::function<bool(const ExceptionRecord&, ps::ContextFrame&)> handler) {
        userSehHandler_ = std::move(handler);
    }

    [[nodiscard]] const BugCheckFrame& getLastBugCheck() const noexcept { return lastBugCheck_; }
    [[nodiscard]] uint64_t getResolvedPageFaults() const noexcept { return pageFaultsResolved_; }
    [[nodiscard]] uint64_t getResolvedCowFaults() const noexcept { return cowFaultsResolved_; }

private:
    TrapEngine() = default;
    std::function<bool(const ExceptionRecord&, ps::ContextFrame&)> debuggerHandler_;
    std::function<bool(const ExceptionRecord&, ps::ContextFrame&)> userSehHandler_;
    BugCheckFrame lastBugCheck_{};
    std::atomic<uint64_t> pageFaultsResolved_{0};
    std::atomic<uint64_t> cowFaultsResolved_{0};
};

inline void KeBugCheckEx(uint32_t code, uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4 = 0) {
    TrapEngine::get().keBugCheckEx(code, p1, p2, p3, p4);
}

} // namespace micant::ke
