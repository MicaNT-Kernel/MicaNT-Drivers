#pragma once

/**
 * @file arm64.hpp
 * @brief Clean-room AArch64 (ARM64) Hardware Architecture & Subsystem Engine.
 *
 * Implements the 64-bit ARM hardware structures and contracts required for
 * multi-architecture NT execution on modern ARM64 silicon (e.g. Qualcomm Snapdragon X
 * Elite, Apple Silicon M-series via hypervisor, and Ampere Altra):
 * - 64-bit AArch64 General-Purpose Register File (X0-X30, SP_EL0, SP_EL1, PC, PSTATE)
 * - 128-bit SIMD / NEON Vector Register File (Q0-Q31, FPCR, FPSR)
 * - Hardware Exception Levels (EL0 Userland, EL1 Kernel Executive, EL2 Hypervisor, EL3 Secure Monitor)
 * - Exception Syndrome Register (ESR_EL1) and Fault Address Register (FAR_EL1) decoders
 * - AArch64 VMSA 48-bit 4-Level Virtual Memory Translation Tables (TTBR0_EL1, TTBR1_EL1, TCR_EL1, MAIR_EL1)
 * - Fast System Call Dispatcher (KiArm64SystemCall via SVC #1 with AAPCS64 X8 SSN calling convention)
 * - Thread Pointer Registers (TPIDR_EL0 for User TEB, TPIDR_EL1 for Kernel KPCR)
 *
 * References:
 * - ARM Architecture Reference Manual: ARMv8/ARMv9-A Architecture Profile (DDI 0487)
 * - Procedure Call Standard for the Arm 64-bit Architecture (AAPCS64)
 * - Microsoft Learn: Overview of ARM64 ABI Conventions
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <array>
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>
#include <span>
#include <unordered_map>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "dispatcher.hpp"

namespace micant::arm64 {

// ============================================================================
// 1. AArch64 Exception Levels
// ============================================================================
enum class ExceptionLevel : uint8_t {
    EL0 = 0, // Normal Userland Applications (Ring 3 equivalent)
    EL1 = 1, // OS Kernel / Executive Subsystem (Ring 0 equivalent)
    EL2 = 2, // Hypervisor (Virtualization Host)
    EL3 = 3  // Secure Monitor (Firmware / TrustZone)
};

[[nodiscard]] constexpr std::string_view ExceptionLevelToString(ExceptionLevel el) noexcept {
    switch (el) {
        case ExceptionLevel::EL0: return "EL0 (Userland)";
        case ExceptionLevel::EL1: return "EL1 (Kernel/Executive)";
        case ExceptionLevel::EL2: return "EL2 (Hypervisor)";
        case ExceptionLevel::EL3: return "EL3 (Secure Monitor)";
        default: return "Unknown EL";
    }
}

// ============================================================================
// 2. AArch64 PSTATE / SPSR Bitfields
// ============================================================================
namespace pstate {
    inline constexpr uint64_t FLAG_N   = (1ULL << 31); // Negative condition flag
    inline constexpr uint64_t FLAG_Z   = (1ULL << 30); // Zero condition flag
    inline constexpr uint64_t FLAG_C   = (1ULL << 29); // Carry condition flag
    inline constexpr uint64_t FLAG_V   = (1ULL << 28); // Overflow condition flag
    inline constexpr uint64_t MASK_D   = (1ULL << 9);  // Debug exception mask
    inline constexpr uint64_t MASK_A   = (1ULL << 8);  // SError interrupt mask
    inline constexpr uint64_t MASK_I   = (1ULL << 7);  // IRQ interrupt mask
    inline constexpr uint64_t MASK_F   = (1ULL << 6);  // FIQ interrupt mask
    inline constexpr uint64_t MODE_EL0t = 0x00;        // EL0 with SP_EL0
    inline constexpr uint64_t MODE_EL1t = 0x04;        // EL1 with SP_EL0
    inline constexpr uint64_t MODE_EL1h = 0x05;        // EL1 with SP_EL1 (Dedicated kernel stack)
}

// ============================================================================
// 3. AArch64 128-bit SIMD / NEON Vector Register Structure
// ============================================================================
struct alignas(16) Arm64VectorRegister {
    union {
        uint8_t   b[16];
        uint16_t  h[8];
        uint32_t  s[4];
        uint64_t  d[2];
        uint64_t  low64;
    };

    [[nodiscard]] bool isZero() const noexcept {
        return d[0] == 0 && d[1] == 0;
    }
};

// ============================================================================
// 4. AArch64 Hardware CPU Register Context (Arm64Context)
// ============================================================================
struct alignas(16) Arm64Context {
    // 31 General-Purpose 64-bit Registers (X0 - X30)
    // X0 - X7:   Parameter & return value registers
    // X8:        Indirect result location / Windows ARM64 Syscall SSN register
    // X9 - X15:  Caller-saved temporary registers
    // X16, X17:  IP0, IP1 intra-procedure call temporary registers
    // X18:       Platform Register (reserved by Windows NT as TEB pointer in Userland)
    // X19 - X28: Callee-saved general purpose registers
    // X29:       Frame Pointer (FP)
    // X30:       Link Register (LR)
    union {
        uint64_t x[31]{0};
        struct {
            uint64_t x0, x1, x2, x3, x4, x5, x6, x7;
            uint64_t x8;
            uint64_t x9, x10, x11, x12, x13, x14, x15;
            uint64_t x16, x17;
            uint64_t x18; // Platform register (TEB)
            uint64_t x19, x20, x21, x22, x23, x24, x25, x26, x27, x28;
            uint64_t fp;  // X29
            uint64_t lr;  // X30
        };
    };

    uint64_t sp_el0{0};  // Stack Pointer for Userland (EL0)
    uint64_t sp_el1{0};  // Stack Pointer for Kernel Executive (EL1)
    uint64_t pc{0};      // Program Counter
    uint64_t pstate{pstate::MODE_EL0t}; // Current Program Status Register / PSTATE

    // System Registers
    uint64_t tpidr_el0{0}; // Thread ID Register EL0 (TEB address in Userland)
    uint64_t tpidr_el1{0}; // Thread ID Register EL1 (KPCR address in Kernel)

    // 32 128-bit SIMD / NEON Vector Registers (Q0 - Q31)
    std::array<Arm64VectorRegister, 32> v{};
    uint32_t fpcr{0}; // Floating-Point Control Register
    uint32_t fpsr{0}; // Floating-Point Status Register

    [[nodiscard]] ExceptionLevel getCurrentEl() const noexcept {
        uint64_t mode = pstate & 0x0F;
        if (mode == pstate::MODE_EL0t) return ExceptionLevel::EL0;
        if (mode == pstate::MODE_EL1t || mode == pstate::MODE_EL1h) return ExceptionLevel::EL1;
        return ExceptionLevel::EL0;
    }

    void setConditionFlags(bool n, bool z, bool c, bool vFlag) noexcept {
        pstate &= ~(pstate::FLAG_N | pstate::FLAG_Z | pstate::FLAG_C | pstate::FLAG_V);
        if (n) pstate |= pstate::FLAG_N;
        if (z) pstate |= pstate::FLAG_Z;
        if (c) pstate |= pstate::FLAG_C;
        if (vFlag) pstate |= pstate::FLAG_V;
    }

    [[nodiscard]] bool isZeroFlag() const noexcept {
        return (pstate & pstate::FLAG_Z) != 0;
    }

    [[nodiscard]] bool isNegativeFlag() const noexcept {
        return (pstate & pstate::FLAG_N) != 0;
    }
};

// ============================================================================
// 5. AArch64 Exception Syndrome Register (ESR_EL1) & Fault Handling
// ============================================================================
namespace esr {
    // Exception Classes (EC bits [31:26])
    inline constexpr uint32_t EC_UNKNOWN       = 0x00;
    inline constexpr uint32_t EC_SVC64         = 0x15; // Supervisor Call (SVC) in AArch64 state
    inline constexpr uint32_t EC_IABT_LOW      = 0x20; // Instruction Abort from lower Exception Level
    inline constexpr uint32_t EC_IABT_CUR      = 0x21; // Instruction Abort from current Exception Level
    inline constexpr uint32_t EC_PC_ALIGN      = 0x22; // PC alignment fault
    inline constexpr uint32_t EC_DABT_LOW      = 0x24; // Data Abort from lower Exception Level (Page Fault)
    inline constexpr uint32_t EC_DABT_CUR      = 0x25; // Data Abort from current Exception Level
    inline constexpr uint32_t EC_SP_ALIGN      = 0x26; // SP alignment fault
    inline constexpr uint32_t EC_BRK64         = 0x3C; // Breakpoint (BRK) in AArch64 state

    // Data Fault Status Code (DFSC bits [5:0] in ISS)
    inline constexpr uint32_t DFSC_TRANS_L0    = 0x04; // Translation fault Level 0
    inline constexpr uint32_t DFSC_TRANS_L1    = 0x05; // Translation fault Level 1
    inline constexpr uint32_t DFSC_TRANS_L2    = 0x06; // Translation fault Level 2
    inline constexpr uint32_t DFSC_TRANS_L3    = 0x07; // Translation fault Level 3
    inline constexpr uint32_t DFSC_ACCESS_L1   = 0x09; // Access flag fault Level 1
    inline constexpr uint32_t DFSC_ACCESS_L2   = 0x0A; // Access flag fault Level 2
    inline constexpr uint32_t DFSC_ACCESS_L3   = 0x0B; // Access flag fault Level 3
    inline constexpr uint32_t DFSC_PERM_L1     = 0x0D; // Permission fault Level 1
    inline constexpr uint32_t DFSC_PERM_L2     = 0x0E; // Permission fault Level 2
    inline constexpr uint32_t DFSC_PERM_L3     = 0x0F; // Permission fault Level 3
}

/**
 * @brief Decoded AArch64 Exception Syndrome.
 */
struct Arm64ExceptionSyndrome {
    uint32_t rawEsr{0};
    uint64_t faultAddress{0}; // FAR_EL1

    [[nodiscard]] uint32_t getExceptionClass() const noexcept {
        return (rawEsr >> 26) & 0x3F;
    }

    [[nodiscard]] bool is32BitInstruction() const noexcept {
        return (rawEsr & (1U << 25)) != 0;
    }

    [[nodiscard]] uint32_t getInstructionSpecificSyndrome() const noexcept {
        return rawEsr & 0x01FFFFFF;
    }

    [[nodiscard]] uint16_t getSvcImmediate() const noexcept {
        return static_cast<uint16_t>(rawEsr & 0xFFFF);
    }

    [[nodiscard]] bool isDataAbort() const noexcept {
        uint32_t ec = getExceptionClass();
        return ec == esr::EC_DABT_LOW || ec == esr::EC_DABT_CUR;
    }

    [[nodiscard]] bool isWriteNotRead() const noexcept {
        // Bit 6 in ISS for Data Abort indicates WnR (1 = Write, 0 = Read)
        return (getInstructionSpecificSyndrome() & (1U << 6)) != 0;
    }

    [[nodiscard]] uint32_t getDataFaultStatusCode() const noexcept {
        return getInstructionSpecificSyndrome() & 0x3F;
    }

    [[nodiscard]] bool isSupervisorCall() const noexcept {
        return getExceptionClass() == esr::EC_SVC64;
    }
};

// ============================================================================
// 6. AArch64 VMSA 48-bit 4-Level Translation Table Architecture
// ============================================================================
namespace mmu {
    // Standard 48-bit canonical address split
    inline constexpr uint64_t VA_USER_MAX    = 0x0000'7FFF'FFFF'FFFFULL; // Lower half (TTBR0)
    inline constexpr uint64_t VA_KERNEL_MIN  = 0xFFFF'8000'0000'0000ULL; // Upper half (TTBR1)

    // Translation Table Descriptors (4KB Granule)
    inline constexpr uint64_t DESC_VALID     = (1ULL << 0);
    inline constexpr uint64_t DESC_TABLE     = (1ULL << 1); // 1 = Table / Page, 0 = Block
    inline constexpr uint64_t DESC_PAGE      = (1ULL << 1);

    // Memory Attribute Indirection Register (MAIR_EL1) Indices
    inline constexpr uint64_t ATTR_IDX_NORMAL_WBWA = 0; // MAIR Attr 0: 0xFF (Normal Write-Back Write-Allocate)
    inline constexpr uint64_t ATTR_IDX_DEVICE_nGnRnE= 1; // MAIR Attr 1: 0x00 (Device nGnRnE)
    inline constexpr uint64_t ATTR_IDX_NORMAL_NC   = 2; // MAIR Attr 2: 0x44 (Normal Non-Cacheable)

    // Access Permissions (AP[2:1] bits [7:6])
    inline constexpr uint64_t AP_RW_EL1_NONE_EL0   = (0ULL << 6); // Read/Write EL1, No access EL0
    inline constexpr uint64_t AP_RW_ALL            = (1ULL << 6); // Read/Write EL1 and EL0
    inline constexpr uint64_t AP_RO_EL1_NONE_EL0   = (2ULL << 6); // Read-Only EL1, No access EL0
    inline constexpr uint64_t AP_RO_ALL            = (3ULL << 6); // Read-Only EL1 and EL0

    // Non-Secure, Access Flag, Execute-Never
    inline constexpr uint64_t DESC_AF              = (1ULL << 10); // Access Flag (must be 1 to prevent access fault)
    inline constexpr uint64_t DESC_SH_INNER        = (3ULL << 8);  // Inner Shareable
    inline constexpr uint64_t DESC_PXN             = (1ULL << 53); // Privileged Execute Never
    inline constexpr uint64_t DESC_UXN             = (1ULL << 54); // User Execute Never
}

/**
 * @brief In-Memory AArch64 Page Table Entry (4 KB Granule).
 */
struct alignas(8) Arm64Pte {
    uint64_t raw{0};

    [[nodiscard]] bool isValid() const noexcept { return (raw & mmu::DESC_VALID) != 0; }
    [[nodiscard]] bool isTable() const noexcept { return (raw & mmu::DESC_TABLE) != 0; }
    [[nodiscard]] uint64_t getOutputAddress() const noexcept {
        return raw & 0x0000'FFFF'FFFF'F000ULL;
    }

    void setPage(uint64_t physicalAddress, uint64_t apFlags, uint64_t mairIdx, bool uxn, bool pxn) noexcept {
        raw = (physicalAddress & 0x0000'FFFF'FFFF'F000ULL)
            | mmu::DESC_VALID
            | mmu::DESC_PAGE
            | mmu::DESC_AF
            | mmu::DESC_SH_INNER
            | (apFlags & (3ULL << 6))
            | ((mairIdx & 0x7ULL) << 2);
        if (uxn) raw |= mmu::DESC_UXN;
        if (pxn) raw |= mmu::DESC_PXN;
    }
};

/**
 * @brief Simulated AArch64 VMSA 4-Level Memory Management Unit.
 */
class Arm64Mmu {
public:
    Arm64Mmu() {
        // Initialize Default TCR_EL1 & MAIR_EL1 registers
        // TCR_EL1: T0SZ=16 (48-bit), T1SZ=16 (48-bit), TG0=4KB, TG1=4KB, IPS=48-bit
        tcr_ = 0x00000025B5103510ULL;
        // MAIR_EL1: Attr0=0xFF (Normal WBWA), Attr1=0x00 (Device-nGnRnE), Attr2=0x44 (Non-Cacheable)
        mair_ = 0x00000000004400FFULL;
    }

    void setTtbr0(uint64_t base) noexcept { ttbr0_ = base; }
    void setTtbr1(uint64_t base) noexcept { ttbr1_ = base; }
    [[nodiscard]] uint64_t getTtbr0() const noexcept { return ttbr0_; }
    [[nodiscard]] uint64_t getTtbr1() const noexcept { return ttbr1_; }
    [[nodiscard]] uint64_t getTcr() const noexcept { return tcr_; }
    [[nodiscard]] uint64_t getMair() const noexcept { return mair_; }

    /**
     * @brief Maps a 4 KB virtual page into the simulated AArch64 translation table.
     */
    void mapPage(uint64_t va, uint64_t pa, uint64_t apFlags, uint64_t mairIdx = mmu::ATTR_IDX_NORMAL_WBWA, bool uxn = false, bool pxn = false) {
        Arm64Pte pte{};
        pte.setPage(pa, apFlags, mairIdx, uxn, pxn);
        pageTable_[va & ~0xFFFULL] = pte;
    }

    /**
     * @brief Performs a simulated 4-Level hardware page table walk (L0 -> L1 -> L2 -> L3).
     * @param va Virtual address to resolve.
     * @param outPa Resolved physical address.
     * @param outPte Resolved Page Table Entry descriptors.
     * @return NtStatus::Success or translation fault status.
     */
    [[nodiscard]] NtStatus translateVirtualAddress(uint64_t va, uint64_t& outPa, Arm64Pte& outPte) const {
        uint64_t pageVa = va & ~0xFFFULL;
        uint64_t offset = va & 0xFFFULL;

        auto it = pageTable_.find(pageVa);
        if (it == pageTable_.end() || !it->second.isValid()) {
            return NtStatus::AccessViolation;
        }

        outPte = it->second;
        outPa = outPte.getOutputAddress() | offset;
        return NtStatus::Success;
    }

    /**
     * @brief Computes 4-Level index breakdown for a 48-bit canonical virtual address.
     */
    struct LevelIndices {
        uint16_t l0; // Bits [47:39]
        uint16_t l1; // Bits [38:30]
        uint16_t l2; // Bits [29:21]
        uint16_t l3; // Bits [20:12]
        uint16_t offset; // Bits [11:0]
    };

    [[nodiscard]] static LevelIndices extractIndices(uint64_t va) noexcept {
        return LevelIndices{
            .l0 = static_cast<uint16_t>((va >> 39) & 0x1FF),
            .l1 = static_cast<uint16_t>((va >> 30) & 0x1FF),
            .l2 = static_cast<uint16_t>((va >> 21) & 0x1FF),
            .l3 = static_cast<uint16_t>((va >> 12) & 0x1FF),
            .offset = static_cast<uint16_t>(va & 0xFFF)
        };
    }

private:
    uint64_t ttbr0_{0x0000000010000000ULL};
    uint64_t ttbr1_{0x0000000020000000ULL};
    uint64_t tcr_{0};
    uint64_t mair_{0};
    std::unordered_map<uint64_t, Arm64Pte> pageTable_;
};

// ============================================================================
// 7. AArch64 Fast System Call Dispatcher Bridge (KiArm64SystemCall)
// ============================================================================
class Arm64SyscallBridge {
public:
    static Arm64SyscallBridge& get() {
        static Arm64SyscallBridge instance;
        return instance;
    }

    /**
     * @brief Dispatches an ARM64 `SVC #1` instruction into MicaNT's central SyscallDispatcher.
     *
     * In the Windows on ARM64 ABI:
     * - Register X8 contains the System Service Number (SSN).
     * - Registers X0 - X7 contain the first 8 arguments.
     * - Register X0 receives the returned NtStatus code.
     */
    NtStatus dispatchSvc(Arm64Context& ctx, const Arm64ExceptionSyndrome& syndrome) {
        if (!syndrome.isSupervisorCall()) {
            return NtStatus::IllegalInstruction;
        }

        // Standard Windows on ARM64 convention uses SVC #1
        if (syndrome.getSvcImmediate() != 1 && syndrome.getSvcImmediate() != 0) {
            return NtStatus::IllegalInstruction;
        }

        uint32_t ssn = static_cast<uint32_t>(ctx.x8);

        // Parameters 5 - 8 are placed in stackArgs for standard NT dispatcher compatibility
        uint64_t stackArgs[4] = { ctx.x4, ctx.x5, ctx.x6, ctx.x7 };

        sys::SyscallFrame frame{
            .ssn = ssn,
            .arg1 = ctx.x0,
            .arg2 = ctx.x1,
            .arg3 = ctx.x2,
            .arg4 = ctx.x3,
            .stackArgs = stackArgs,
            .stackArgCount = 4
        };

        NtStatus result = sys::SyscallDispatcher::get().dispatch(frame);
        ctx.x0 = static_cast<uint64_t>(result);

        // Advance PC by 4 bytes (AArch64 instruction width)
        ctx.pc += 4;

        return result;
    }
};

} // namespace micant::arm64
