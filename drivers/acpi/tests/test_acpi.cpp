// ============================================================================
// Standalone Driver Verification Test: acpi (TitanACPI / AegisACPI)
// Subsystem: ACPI 6.5 Platform & AML Interpreter Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/acpi.hpp"

using namespace micant;

static int g_PassedTests = 0;
static int g_FailedTests = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "  [FAIL] " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            g_FailedTests++; \
            return; \
        } \
    } while (0)

#define RUN_TEST(fn) \
    do { \
        std::cout << "[RUNNING] " << #fn << "...\n" << std::flush; \
        int before = g_FailedTests; \
        fn(); \
        if (g_FailedTests == before) { \
            std::cout << "  [PASS] " << #fn << "\n" << std::flush; \
            g_PassedTests++; \
        } \
    } while (0)

void Test_ACPI_Platform_And_AML_Interpreter_Subsystem() {
    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 154: ACPI 6.5 Platform Subsystem & AML Interpreter              \n";
    std::cout << "========================================================================\n";

    // Initialize Subsystem
    acpi::InitializeAcpiSubsystem();
    auto& acpiSub = acpi::TitanAcpiSubsystem::Instance();
    TEST_ASSERT(acpiSub.isInitialized(), "TitanACPI subsystem must be initialized");

    // Stage 1: RSDP Structure & Extended Checksum Verification
    const auto& rsdp = acpiSub.getRsdp();
    TEST_ASSERT(std::memcmp(rsdp.signature, acpi::ACPI_SIG_RSDP, 8) == 0, "RSDP signature must be 'RSD PTR '");
    TEST_ASSERT(std::memcmp(rsdp.oemId, "MICANT", 6) == 0, "RSDP OEM ID must match MICANT");
    TEST_ASSERT(rsdp.revision == 2, "RSDP revision must be 2 (ACPI 2.0+)");
    TEST_ASSERT(acpi::VerifyAcpiChecksum(&rsdp, 20), "ACPI 1.0 RSDP 20-byte checksum must equal 0 (mod 256)");
    TEST_ASSERT(acpi::VerifyAcpiChecksum(&rsdp, sizeof(acpi::AcpiRsdp)), "ACPI 2.0+ Extended 36-byte RSDP checksum must equal 0 (mod 256)");
    TEST_ASSERT(rsdp.xsdtAddress != 0, "XSDT 64-bit physical address must be populated");

    // Stage 2: Fixed ACPI Description Table (FADT / FACP)
    const auto& fadt = acpiSub.getFadt();
    TEST_ASSERT(std::memcmp(fadt.header.signature, "FACP", 4) == 0, "FADT signature must be 'FACP'");
    TEST_ASSERT(fadt.header.revision == 6, "FADT revision must be 6 (ACPI 6.x)");
    TEST_ASSERT(acpi::VerifyAcpiChecksum(&fadt, sizeof(acpi::AcpiFadt)), "FADT checksum must be valid");
    TEST_ASSERT(fadt.preferredPmProfile == acpi::PM_PROFILE_ENTERPRISE_SERVER, "Preferred PM Profile must match Enterprise Server");
    TEST_ASSERT(fadt.sciInt == 9, "SCI interrupt vector must be IRQ 9");
    TEST_ASSERT(fadt.pmTmrBlk == 0x0408, "PM Timer I/O block must be 0x0408");
    TEST_ASSERT(fadt.resetReg.address == 0x0CF9, "Reset register address must be 0x0CF9");
    TEST_ASSERT(fadt.resetValue == 0x06, "Reset value must be 0x06 (Full Reset)");

    // Stage 3: Multiple APIC Description Table (MADT / APIC) - SMP Cores
    const auto& madtHdr = acpiSub.getMadtHeader();
    TEST_ASSERT(std::memcmp(madtHdr.header.signature, "APIC", 4) == 0, "MADT signature must be 'APIC'");
    TEST_ASSERT(madtHdr.localApicAddress == 0xFEE00000, "Local APIC default physical address must be 0xFEE00000");

    const auto& lapics = acpiSub.getLocalApics();
    TEST_ASSERT(lapics.size() == 4, "MADT must enumerate exactly 4 Local APICs (SMP Cores)");
    for (size_t i = 0; i < lapics.size(); ++i) {
        TEST_ASSERT(lapics[i].processorId == i, "Processor ID must match core index");
        TEST_ASSERT(lapics[i].apicId == i, "APIC ID must match core index");
        TEST_ASSERT((lapics[i].flags & 1) != 0, "Local APIC must be marked Enabled");
    }

    // Stage 4: I/O APIC & Interrupt Source Overrides
    const auto& ioapics = acpiSub.getIoApics();
    TEST_ASSERT(ioapics.size() == 1, "MADT must enumerate 1 primary I/O APIC");
    TEST_ASSERT(ioapics[0].ioApicAddress == 0xFEC00000, "I/O APIC physical address must be 0xFEC00000");
    TEST_ASSERT(ioapics[0].gsiBase == 0, "I/O APIC GSI base must be 0");

    const auto& overrides = acpiSub.getIntrOverrides();
    TEST_ASSERT(overrides.size() >= 2, "MADT must contain at least 2 Interrupt Source Overrides (IRQ0 and IRQ9)");
    TEST_ASSERT(overrides[0].source == 0 && overrides[0].gsi == 2, "IRQ 0 (PIT Timer) must override to GSI 2");
    TEST_ASSERT(overrides[1].source == 9 && overrides[1].gsi == 9, "IRQ 9 (ACPI SCI) must override to GSI 9");

    // Stage 5: PCI Express Memory Mapped Configuration Mechanism (MCFG)
    const auto& mcfg = acpiSub.getMcfg();
    TEST_ASSERT(std::memcmp(mcfg.header.signature, "MCFG", 4) == 0, "MCFG signature must be 'MCFG'");
    TEST_ASSERT(mcfg.allocations[0].baseAddress == 0xE0000000ULL, "PCIe ECAM MMIO base address must be 0xE0000000");
    TEST_ASSERT(mcfg.allocations[0].startBusNumber == 0, "PCIe start bus must be 0");
    TEST_ASSERT(mcfg.allocations[0].endBusNumber == 255, "PCIe end bus must be 255");

    // Stage 6: DMA Remapping (DMAR) & NUMA Proximity (SRAT)
    const auto& dmar = acpiSub.getDmar();
    TEST_ASSERT(std::memcmp(dmar.header.signature, "DMAR", 4) == 0, "DMAR signature must be 'DMAR'");
    TEST_ASSERT(dmar.hostAddressWidth >= 39, "DMAR host address width must be >= 39 bits");
    TEST_ASSERT((dmar.flags & 0x01) != 0, "DMAR Interrupt Remapping must be supported");

    const auto& srat = acpiSub.getSrat();
    TEST_ASSERT(std::memcmp(srat.header.signature, "SRAT", 4) == 0, "SRAT signature must be 'SRAT'");

    // Stage 7: AML Namespace Tree Walk (_SB, _PR, _TZ)
    const auto& ns = acpiSub.getNamespace();
    auto root = ns.getRoot();
    TEST_ASSERT(root != nullptr, "ACPI Namespace root must exist");
    TEST_ASSERT(ns.resolvePath("\\_SB") != nullptr, "\\_SB scope must exist");
    TEST_ASSERT(ns.resolvePath("\\_PR") != nullptr, "\\_PR scope must exist");
    TEST_ASSERT(ns.resolvePath("\\_TZ") != nullptr, "\\_TZ scope must exist");

    auto pci0 = ns.resolvePath("\\_SB.PCI0");
    TEST_ASSERT(pci0 != nullptr, "\\_SB.PCI0 device must exist");
    auto nvmeDev = ns.resolvePath("\\_SB.PCI0.NVME");
    TEST_ASSERT(nvmeDev != nullptr, "\\_SB.PCI0.NVME child device must exist");
    auto gpuDev = ns.resolvePath("\\_SB.PCI0.GFX0");
    TEST_ASSERT(gpuDev != nullptr, "\\_SB.PCI0.GFX0 child device must exist");

    // Stage 8: Operating System Interface (_OSI) Evaluation
    auto osiWin11 = ns.evaluate("\\_OSI", { acpi::AmlValue::MakeString("Windows 2022") });
    TEST_ASSERT(osiWin11.integerVal == 0xFFFFFFFFULL, "_OSI('Windows 2022') must return true (0xFFFFFFFF)");

    auto osiMica = ns.evaluate("\\_OSI", { acpi::AmlValue::MakeString("MicaNT") });
    TEST_ASSERT(osiMica.integerVal == 0xFFFFFFFFULL, "_OSI('MicaNT') must return true (0xFFFFFFFF)");

    auto osiUnknown = ns.evaluate("\\_OSI", { acpi::AmlValue::MakeString("OS/2 Warp") });
    TEST_ASSERT(osiUnknown.integerVal == 0, "_OSI('OS/2 Warp') must return 0 (unsupported)");

    // Stage 9: Thermal Zone (_TMP, _CRT, _AC0) Telemetry
    uint32_t tenthsK = 0;
    auto bTmp = acpi::AcpiGetThermalZoneTemp(&tenthsK);
    TEST_ASSERT(bTmp == win32::TRUE, "AcpiGetThermalZoneTemp must succeed");
    TEST_ASSERT(tenthsK == 3182, "_TMP must return 3182 (318.2 K = 45.0 C)");

    auto crtVal = ns.evaluate("\\_TZ.TZ00._CRT");
    TEST_ASSERT(crtVal.integerVal == 3732, "_CRT trip point must be 3732 (100.0 C)");

    auto ac0Val = ns.evaluate("\\_TZ.TZ00._AC0");
    TEST_ASSERT(ac0Val.integerVal == 3282, "_AC0 trip point must be 3282 (55.0 C)");

    // Stage 10: Smart Battery Subsystem (_BST & _BIF)
    uint32_t bState = 0, bRate = 0, bCap = 0, bVolt = 0;
    auto bBat = acpi::AcpiGetBatteryStatus(&bState, &bRate, &bCap, &bVolt);
    TEST_ASSERT(bBat == win32::TRUE, "AcpiGetBatteryStatus must succeed");
    TEST_ASSERT(bCap == 75000, "Battery remaining capacity must report 75000 mWh");
    TEST_ASSERT(bVolt == 15400, "Battery voltage must report 15400 mV (15.4V)");

    // Stage 11: System Power State Transitions (_PTS / _WAK S0-S5)
    uint8_t pState = 0xFF;
    acpi::AcpiGetSystemPowerState(&pState);
    TEST_ASSERT(pState == 0, "Initial power state must be S0 (Working)");

    auto bSleep = acpi::AcpiSetSystemPowerState(3); // Transition S3
    TEST_ASSERT(bSleep == win32::TRUE, "Transition to S3 Suspend-to-RAM must succeed");
    acpi::AcpiGetSystemPowerState(&pState);
    TEST_ASSERT(pState == 0, "Power state must return to S0 after wake handshake");

    // Stage 12: Dynamic Loader Module Exports in acpi.sys & SCM Driver Record
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("acpi.sys", "AcpiFindTable") != nullptr, "acpi.sys AcpiFindTable export must exist");
    TEST_ASSERT(ldr.getExport("acpi.sys", "AcpiEvaluateObject") != nullptr, "acpi.sys AcpiEvaluateObject export must exist");
    TEST_ASSERT(ldr.getExport("acpi.sys", "AcpiGetSystemPowerState") != nullptr, "acpi.sys AcpiGetSystemPowerState export must exist");
    TEST_ASSERT(ldr.getExport("acpi.sys", "AcpiSetSystemPowerState") != nullptr, "acpi.sys AcpiSetSystemPowerState export must exist");
    TEST_ASSERT(ldr.getExport("acpi.sys", "AcpiGetThermalZoneTemp") != nullptr, "acpi.sys AcpiGetThermalZoneTemp export must exist");
    TEST_ASSERT(ldr.getExport("acpi.sys", "AcpiGetBatteryStatus") != nullptr, "acpi.sys AcpiGetBatteryStatus export must exist");
    TEST_ASSERT(ldr.getExport("acpi.sys", "AcpiGetProcessorCount") != nullptr, "acpi.sys AcpiGetProcessorCount export must exist");

    auto acpiSvc = scm::ServiceControlManager::get().getServiceRecord(L"acpi");
    TEST_ASSERT(acpiSvc != nullptr, "acpi service record must exist in SCM");
    TEST_ASSERT(acpiSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "acpi service type must be kernel driver");
    TEST_ASSERT(acpiSvc->startType == scm::SERVICE_BOOT_START, "acpi service start type must be boot start");

    auto acpiVer = version::VersionDatabase::Instance().GetModuleInfo("acpi.sys");
    TEST_ASSERT(acpiVer != nullptr, "acpi.sys must be registered in Version Database");
    TEST_ASSERT(acpiVer->stringTable.count("FileVersion") > 0, "acpi.sys FileVersion must exist");

    std::cout << "[TEST] Suite 154: ACPI 6.5 Platform Subsystem & AML Interpreter PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: ACPI 6.5 Platform & AML Interpreter Subsystem\n";
    std::cout << "       Codename: TitanACPI / AegisACPI | Binary: acpi.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_ACPI_Platform_And_AML_Interpreter_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
