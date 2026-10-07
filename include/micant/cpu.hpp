#pragma once

/**
 * @file cpu.hpp
 * @brief Clean-room x86-64 Hardware Architecture & Ring 3 User-Mode Transition Engine.
 *
 * Implements the hardware structures required to boot and switch privilege levels
 * between Ring 0 (Kernel Executive) and Ring 3 (Userland Applications):
 * - Global Descriptor Table (GDT) with standard 64-bit Windows selectors
 * - 64-bit Task State Segment (TSS64) and interrupt stack tables (IST)
 * - Model-Specific Registers (MSRs) for KiSystemCall64 (STAR, LSTAR, SFMASK, EFER)
 * - User-Mode Entry Trampolines (iretq and sysretq frames)
 *
 * Reference: AMD64 Architecture Programmer's Manual, Vol 2: System Programming (Pub 24593)
 *            Intel 64 and IA-32 Architectures Software Developer's Manual, Vol 3A
 */

#include <cstdint>
#include <string_view>
#include <array>
#include <cstring>
#include "ntdef.hpp"
#include "ntstatus.hpp"

namespace micant::cpu {

// ============================================================================
// 1. x86-64 Segment Selectors (Standard Windows NT Layout)
// ============================================================================
inline constexpr uint16_t KGDT64_NULL         = 0x0000;
inline constexpr uint16_t KGDT64_R0_CODE      = 0x0010; // Kernel Code (CS: Ring 0, DPL 0)
inline constexpr uint16_t KGDT64_R0_DATA      = 0x0018; // Kernel Data (DS/SS: Ring 0, DPL 0)
inline constexpr uint16_t KGDT64_R3_CMCODE    = 0x0020; // Compatibility Mode Code 32-bit (Ring 3, DPL 3)
inline constexpr uint16_t KGDT64_R3_DATA      = 0x0028; // User Data (DS/SS: Ring 3, DPL 3, RPL 3 = 0x002B)
inline constexpr uint16_t KGDT64_R3_CODE      = 0x0030; // User Code 64-bit (CS: Ring 3, DPL 3, RPL 3 = 0x0033)
inline constexpr uint16_t KGDT64_SYS_TSS      = 0x0040; // 64-bit Task State Segment (TSS64, 16 bytes)

inline constexpr uint16_t SELECTOR_KCODE64    = KGDT64_R0_CODE;
inline constexpr uint16_t SELECTOR_KDATA64    = KGDT64_R0_DATA;
inline constexpr uint16_t SELECTOR_UDATA64    = static_cast<uint16_t>(KGDT64_R3_DATA | 0x3);   // 0x002B
inline constexpr uint16_t SELECTOR_UCODE64    = static_cast<uint16_t>(KGDT64_R3_CODE | 0x3);   // 0x0033
inline constexpr uint16_t SELECTOR_UCODE32    = static_cast<uint16_t>(KGDT64_R3_CMCODE | 0x3); // 0x0023 (HeavensGate)
inline constexpr uint16_t SELECTOR_TSS64      = KGDT64_SYS_TSS;

// ============================================================================
// 2. x86-64 Model-Specific Registers (MSRs) for Fast System Calls
// ============================================================================
inline constexpr uint32_t MSR_EFER            = 0xC0000080; // Extended Feature Enable Register
inline constexpr uint32_t MSR_STAR            = 0xC0000081; // Target Selectors for syscall / sysret
inline constexpr uint32_t MSR_LSTAR           = 0xC0000082; // Long Mode Syscall Target RIP (KiSystemCall64)
inline constexpr uint32_t MSR_CSTAR           = 0xC0000083; // Compatibility Mode Syscall Target RIP
inline constexpr uint32_t MSR_SFMASK          = 0xC0000084; // System Call Flag Mask
inline constexpr uint32_t MSR_FS_BASE         = 0xC0000100; // FS Base (TEB32 in WoW64)
inline constexpr uint32_t MSR_GS_BASE         = 0xC0000101; // GS Base (TEB64 in User Mode)
inline constexpr uint32_t MSR_KERNEL_GS_BASE  = 0xC0000102; // Kernel GS Base (KPCR in Kernel Mode)

// RFLAGS bits cleared automatically upon syscall instruction entry
inline constexpr uint64_t SFMASK_DEFAULT      = 0x00004700ULL; // IF (0x200), TF (0x100), DF (0x400), NT (0x4000)

// EFER Bits
inline constexpr uint64_t EFER_SCE            = (1ULL << 0);  // System Call Extensions (syscall/sysret enabled)
inline constexpr uint64_t EFER_LME            = (1ULL << 8);  // Long Mode Enable
inline constexpr uint64_t EFER_LMA            = (1ULL << 10); // Long Mode Active
inline constexpr uint64_t EFER_NXE            = (1ULL << 11); // No-Execute Enable

#pragma pack(push, 1)

// ============================================================================
// 3. Segment Descriptors & TSS Structure
// ============================================================================

struct SegmentDescriptor64 {
    uint16_t limitLow{0xFFFF};
    uint16_t baseLow{0};
    uint8_t  baseMiddle{0};
    uint8_t  access{0};
    uint8_t  limitHighAndFlags{0};
    uint8_t  baseHigh{0};
};

struct TssDescriptor64 {
    uint16_t limitLow{0};
    uint16_t baseLow{0};
    uint8_t  baseMiddle{0};
    uint8_t  access{0x89}; // Present, 64-bit TSS (Available)
    uint8_t  limitHighAndFlags{0};
    uint8_t  baseHigh{0};
    uint32_t baseUpper{0};
    uint32_t reserved{0};
};

struct TaskStateSegment64 {
    uint32_t reserved0{0};
    uint64_t rsp0{0}; // Ring 0 Kernel Stack Pointer (loaded on interrupt / syscall from Ring 3)
    uint64_t rsp1{0};
    uint64_t rsp2{0};
    uint64_t reserved1{0};
    uint64_t ist1{0}; // Interrupt Stack Table 1 (Double Fault #DF)
    uint64_t ist2{0}; // Interrupt Stack Table 2 (NMI)
    uint64_t ist3{0}; // Interrupt Stack Table 3 (Machine Check #MC)
    uint64_t ist4{0};
    uint64_t ist5{0};
    uint64_t ist6{0};
    uint64_t ist7{0};
    uint64_t reserved2{0};
    uint16_t reserved3{0};
    uint16_t ioMapBase{sizeof(TaskStateSegment64)}; // No I/O permission bitmap
};

struct GdtTable64 {
    SegmentDescriptor64 nullDesc{};      // 0x00: Null
    SegmentDescriptor64 kernelCode{};    // 0x10: Kernel Code 64
    SegmentDescriptor64 kernelData{};    // 0x18: Kernel Data 64
    SegmentDescriptor64 userCmCode{};    // 0x20: User Code 32 (WoW64)
    SegmentDescriptor64 userData{};      // 0x28: User Data
    SegmentDescriptor64 userCode{};      // 0x30: User Code 64
    TssDescriptor64     tssDesc{};       // 0x40: 64-bit TSS (16 bytes)
};

struct Gdtr64 {
    uint16_t limit{sizeof(GdtTable64) - 1};
    uint64_t base{0};
};

struct IretFrame64 {
    uint64_t rip{0};    // Target userland Instruction Pointer
    uint64_t cs{0};     // User Code Selector (0x0033)
    uint64_t rflags{0}; // User RFLAGS (0x0202: IF enabled, IOPL 0)
    uint64_t rsp{0};    // Target userland Stack Pointer
    uint64_t ss{0};     // User Data Selector (0x002B)
};

#pragma pack(pop)

// ============================================================================
// 4. Clean-Room CPU Hardware & Ring 3 Control Manager
// ============================================================================

class CpuHardwareEngine {
private:
    GdtTable64 m_gdt{};
    TaskStateSegment64 m_tss{};
    Gdtr64 m_gdtr{};
    uint64_t m_msrStar{0};
    uint64_t m_msrLstar{0};
    uint64_t m_msrSfmask{SFMASK_DEFAULT};
    uint64_t m_msrEfer{EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE};
    bool m_initialized{false};

public:
    static CpuHardwareEngine& get() {
        static CpuHardwareEngine s_instance;
        return s_instance;
    }

    void initialize(uint64_t kernelStackTop, uint64_t kiSystemCall64Address) {
        // 1. Initialize Task State Segment (TSS64)
        std::memset(&m_tss, 0, sizeof(m_tss));
        m_tss.rsp0 = kernelStackTop;
        m_tss.ist1 = kernelStackTop; // Safe IST stack for faults
        m_tss.ioMapBase = sizeof(TaskStateSegment64);

        // 2. Initialize GDT entries
        std::memset(&m_gdt, 0, sizeof(m_gdt));

        // 0x10: Kernel Code 64 (Execute/Read, 64-bit Long Mode, DPL 0)
        m_gdt.kernelCode.limitLow = 0xFFFF;
        m_gdt.kernelCode.access = 0x9A; // Present, Ring 0, Code, Exec/Read
        m_gdt.kernelCode.limitHighAndFlags = 0xAF; // 4KB Granularity, 64-bit Long Mode (L=1, D=0)

        // 0x18: Kernel Data 64 (Read/Write, DPL 0)
        m_gdt.kernelData.limitLow = 0xFFFF;
        m_gdt.kernelData.access = 0x92; // Present, Ring 0, Data, Read/Write
        m_gdt.kernelData.limitHighAndFlags = 0xCF; // 4KB Granularity, 32/64 bit

        // 0x20: User Compatibility Mode Code 32-bit (Ring 3, DPL 3, L=0, D=1)
        m_gdt.userCmCode.limitLow = 0xFFFF;
        m_gdt.userCmCode.access = 0xFA; // Present, Ring 3, Code, Exec/Read
        m_gdt.userCmCode.limitHighAndFlags = 0xCF; // 4KB Granularity, 32-bit (D=1, L=0)

        // 0x28: User Data 64-bit (Ring 3, DPL 3, Read/Write)
        m_gdt.userData.limitLow = 0xFFFF;
        m_gdt.userData.access = 0xF2; // Present, Ring 3, Data, Read/Write
        m_gdt.userData.limitHighAndFlags = 0xCF;

        // 0x30: User Code 64-bit (Ring 3, DPL 3, 64-bit Long Mode, L=1, D=0)
        m_gdt.userCode.limitLow = 0xFFFF;
        m_gdt.userCode.access = 0xFA; // Present, Ring 3, Code, Exec/Read
        m_gdt.userCode.limitHighAndFlags = 0xAF; // 4KB Granularity, 64-bit Long Mode (L=1, D=0)

        // 0x40: TSS64 Descriptor (16-byte System Segment)
        uint64_t tssBase = reinterpret_cast<uint64_t>(&m_tss);
        m_gdt.tssDesc.limitLow = sizeof(TaskStateSegment64) - 1;
        m_gdt.tssDesc.baseLow = static_cast<uint16_t>(tssBase & 0xFFFF);
        m_gdt.tssDesc.baseMiddle = static_cast<uint8_t>((tssBase >> 16) & 0xFF);
        m_gdt.tssDesc.access = 0x89; // Present, 64-bit TSS (Available)
        m_gdt.tssDesc.limitHighAndFlags = 0x00;
        m_gdt.tssDesc.baseHigh = static_cast<uint8_t>((tssBase >> 24) & 0xFF);
        m_gdt.tssDesc.baseUpper = static_cast<uint32_t>((tssBase >> 32) & 0xFFFFFFFF);
        m_gdt.tssDesc.reserved = 0;

        // GDTR
        m_gdtr.limit = sizeof(GdtTable64) - 1;
        m_gdtr.base = reinterpret_cast<uint64_t>(&m_gdt);

        // 3. Program MSRs for KiSystemCall64
        // MSR_STAR format:
        // Bits 47:32 = Kernel CS (0x10) and SS (0x10 + 8 = 0x18) on syscall
        // Bits 63:48 = User CS/SS base on sysret ((0x20 + 16) = 0x30 for 64-bit, SS = 0x28)
        m_msrStar = (static_cast<uint64_t>(KGDT64_R3_CMCODE) << 48) |
                    (static_cast<uint64_t>(KGDT64_R0_CODE) << 32);

        m_msrLstar = kiSystemCall64Address;
        m_msrSfmask = SFMASK_DEFAULT;

        m_initialized = true;
    }

    [[nodiscard]] IretFrame64 createRing3EntryFrame(uint64_t entryPoint, uint64_t userStackPointer) const noexcept {
        IretFrame64 frame{};
        frame.rip = entryPoint;
        frame.cs = SELECTOR_UCODE64;    // 0x0033 (Ring 3 CS)
        frame.rflags = 0x00000202ULL;   // IF (bit 9) enabled, IOPL 0
        frame.rsp = userStackPointer;
        frame.ss = SELECTOR_UDATA64;    // 0x002B (Ring 3 SS)
        return frame;
    }

    [[nodiscard]] bool isInitialized() const noexcept { return m_initialized; }
    [[nodiscard]] const GdtTable64& getGdt() const noexcept { return m_gdt; }
    [[nodiscard]] const TaskStateSegment64& getTss() const noexcept { return m_tss; }
    [[nodiscard]] const Gdtr64& getGdtr() const noexcept { return m_gdtr; }
    [[nodiscard]] uint64_t getMsrStar() const noexcept { return m_msrStar; }
    [[nodiscard]] uint64_t getMsrLstar() const noexcept { return m_msrLstar; }
    [[nodiscard]] uint64_t getMsrSfmask() const noexcept { return m_msrSfmask; }
    [[nodiscard]] uint64_t getMsrEfer() const noexcept { return m_msrEfer; }
};

} // namespace micant::cpu
