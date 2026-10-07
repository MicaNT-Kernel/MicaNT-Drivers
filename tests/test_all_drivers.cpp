// ============================================================================
// MicaNT-Drivers: Master Driver Verification Test Suite
// Verifies all 26+ sovereign hardware, bus, and accelerator drivers in sequence.
// ============================================================================

#include <iostream>
#include <cstdint>
#include <string>
#include <vector>

#include "micant/acpi.hpp"
#include "micant/amx.hpp"
#include "micant/bthport.hpp"
#include "micant/bypassio.hpp"
#include "micant/cet.hpp"
#include "micant/cxl.hpp"
#include "micant/dsa.hpp"
#include "micant/wddm.hpp"
#include "micant/hdaudio.hpp"
#include "micant/hfi.hpp"
#include "micant/iommu.hpp"
#include "micant/ndis.hpp"
#include "micant/npu.hpp"
#include "micant/nvme.hpp"
#include "micant/pci.hpp"
#include "micant/pluton.hpp"
#include "micant/pmem.hpp"
#include "micant/qat.hpp"
#include "micant/rdma.hpp"
#include "micant/sriov.hpp"
#include "micant/tee.hpp"
#include "micant/ucsi.hpp"
#include "micant/usb.hpp"
#include "micant/usb4.hpp"
#include "micant/wdf.hpp"
#include "micant/wdiwifi.hpp"

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

// Extracted Test Declarations & Bodies
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

void Test_IntelAMX_ArmSME_MatrixAccelerator_Subsystem() {
    std::cout << "[TEST] Starting Suite 173: Intel AMX & Arm SME Matrix Accelerator Subsystem...\n";

    auto& amxSub = micant::amx::TitanMatrixSubsystem::Instance();

    // Stage 1: Hardware Capabilities & Subsystem Discovery
    bool initOk = amxSub.initialize();
    TEST_ASSERT(initOk, "TitanMatrixSubsystem initialization must succeed");

    const auto& caps = amxSub.getCapabilities();
    TEST_ASSERT(caps.hasAmxTile, "AMX-TILE feature must be supported");
    TEST_ASSERT(caps.hasAmxInt8, "AMX-INT8 TMUL feature must be supported");
    TEST_ASSERT(caps.hasAmxBf16, "AMX-BF16 precision must be supported");
    TEST_ASSERT(caps.hasAmxFp16, "AMX-FP16 precision must be supported");
    TEST_ASSERT(caps.hasArmSme, "Arm SME feature must be supported");
    TEST_ASSERT(caps.maxTiles == micant::amx::AMX_MAX_TILES, "Max tiles must be 8 (TMM0..TMM7)");
    TEST_ASSERT(caps.maxRows == micant::amx::AMX_MAX_ROWS, "Max rows must be 16");
    TEST_ASSERT(caps.maxColsBytes == micant::amx::AMX_MAX_COLS_BYTES, "Max bytes per row must be 64");
    TEST_ASSERT(caps.totalTileFileBytes == micant::amx::AMX_TOTAL_TILE_BYTES, "Total tile file must be 8192 bytes");

    // Stage 2: Initial Palette State & Zero Initialization
    const auto& initCfg = amxSub.getCurrentConfig();
    TEST_ASSERT(initCfg.paletteId == micant::amx::AMX_PALETTE_ID_NONE, "Initial palette ID must be 0 (unconfigured)");
    for (uint32_t i = 0; i < micant::amx::AMX_MAX_TILES; ++i) {
        TEST_ASSERT(initCfg.rows[i] == 0, "Initial tile rows must be 0");
        TEST_ASSERT(initCfg.colsb[i] == 0, "Initial tile colsb must be 0");
    }

    // Stage 3: Tile Configuration Validation (Palette 1)
    micant::amx::TileConfig cfg{};
    cfg.paletteId = micant::amx::AMX_PALETTE_ID_1;
    cfg.rows[0] = 16; cfg.colsb[0] = 64; // TMM0
    cfg.rows[1] = 16; cfg.colsb[1] = 64; // TMM1
    cfg.rows[2] = 16; cfg.colsb[2] = 64; // TMM2
    int32_t cfgStat = amxSub.configurePalette(cfg);
    TEST_ASSERT(cfgStat == micant::amx::STATUS_SUCCESS, "Configuring Palette 1 must succeed");
    TEST_ASSERT(amxSub.getCurrentConfig().paletteId == micant::amx::AMX_PALETTE_ID_1, "Palette 1 must be active");

    // Stage 4: Invalid Palette ID Rejection
    micant::amx::TileConfig badCfg = cfg;
    badCfg.paletteId = 5;
    int32_t badStat = amxSub.configurePalette(badCfg);
    TEST_ASSERT(badStat == micant::amx::STATUS_INVALID_PARAMETER, "Invalid palette ID must return STATUS_INVALID_PARAMETER");

    // Stage 5: Row/Col Bounds Checking
    micant::amx::TileConfig oobRowCfg = cfg;
    oobRowCfg.rows[0] = 17; // Max is 16
    TEST_ASSERT(amxSub.configurePalette(oobRowCfg) == micant::amx::STATUS_INVALID_PARAMETER, "Rows > 16 must fail");

    micant::amx::TileConfig oobColCfg = cfg;
    oobColCfg.colsb[0] = 65; // Max is 64
    TEST_ASSERT(amxSub.configurePalette(oobColCfg) == micant::amx::STATUS_INVALID_PARAMETER, "Cols > 64 must fail");

    micant::amx::TileConfig zeroRowColMismatch = cfg;
    zeroRowColMismatch.rows[3] = 8;
    zeroRowColMismatch.colsb[3] = 0;
    TEST_ASSERT(amxSub.configurePalette(zeroRowColMismatch) == micant::amx::STATUS_INVALID_PARAMETER, "Row > 0 with Col == 0 must fail");

    // Restore valid Palette 1 configuration
    amxSub.configurePalette(cfg);

    // Stage 6: Tile Load Operation (TILELOADD)
    std::vector<uint8_t> loadData(16 * 64, 0x42);
    int32_t loadStat = amxSub.loadTile(1, loadData.data(), 64);
    TEST_ASSERT(loadStat == micant::amx::STATUS_SUCCESS, "loadTile into TMM1 must succeed");
    const auto& rawTile1 = amxSub.getTileRaw(1);
    TEST_ASSERT(rawTile1.data[0][0] == 0x42, "TMM1 byte [0][0] must match 0x42");
    TEST_ASSERT(rawTile1.data[15][63] == 0x42, "TMM1 byte [15][63] must match 0x42");

    // Stage 7: Tile Store Operation (TILESTORED)
    std::vector<uint8_t> storeData(16 * 64, 0x00);
    int32_t storeStat = amxSub.storeTile(1, storeData.data(), 64);
    TEST_ASSERT(storeStat == micant::amx::STATUS_SUCCESS, "storeTile from TMM1 must succeed");
    TEST_ASSERT(storeData[0] == 0x42, "Stored data byte 0 must match 0x42");
    TEST_ASSERT(storeData[16 * 64 - 1] == 0x42, "Stored data last byte must match 0x42");

    // Stage 8: INT8 Dot Product Matrix Multiplication (TDPBUSD / TMUL)
    std::vector<int8_t> int8MatA(16 * 64, 2);
    std::vector<int8_t> int8MatB(16 * 64, 3);
    amxSub.loadTile(1, int8MatA.data(), 64);
    amxSub.loadTile(2, int8MatB.data(), 64);
    uint32_t int8Lat = 0;
    int32_t int8Stat = amxSub.multiplyInt8(0, 1, 2, true, true, &int8Lat);
    TEST_ASSERT(int8Stat == micant::amx::STATUS_SUCCESS, "multiplyInt8 must succeed");
    TEST_ASSERT(int8Lat == 14, "INT8 systolic latency must be 14 ns");
    std::vector<int32_t> int8Dst(16 * 16, 0);
    amxSub.storeTile(0, int8Dst.data(), 64);
    // Expected element: 16 iterations * 4 elements per tuple * (2 * 3) = 64 * 6 = 384
    TEST_ASSERT(int8Dst[0] == 384, "INT8 dot product element [0] must equal 384");

    // Stage 9: BFloat16 Matrix Multiplication (TDPBF16PS)
    std::vector<uint16_t> bf16MatA(16 * 32, micant::amx::FloatToBf16(1.5f));
    std::vector<uint16_t> bf16MatB(16 * 32, micant::amx::FloatToBf16(2.0f));
    amxSub.loadTile(1, bf16MatA.data(), 64);
    amxSub.loadTile(2, bf16MatB.data(), 64);
    // Clear accumulator tile TMM0
    std::vector<uint8_t> zeroTile(16 * 64, 0);
    amxSub.loadTile(0, zeroTile.data(), 64);
    uint32_t bf16Lat = 0;
    int32_t bf16Stat = amxSub.multiplyBf16(0, 1, 2, &bf16Lat);
    TEST_ASSERT(bf16Stat == micant::amx::STATUS_SUCCESS, "multiplyBf16 must succeed");
    TEST_ASSERT(bf16Lat == 16, "BF16 systolic latency must be 16 ns");
    std::vector<float> bf16Dst(16 * 16, 0.0f);
    amxSub.storeTile(0, bf16Dst.data(), 64);
    // Expected element: 16 iterations * 2 elements per pair * (1.5 * 2.0) = 32 * 3.0 = 96.0f
    TEST_ASSERT(std::fabs(bf16Dst[0] - 96.0f) < 0.001f, "BF16 dot product element [0] must equal 96.0f");

    // Stage 10: IEEE FP16 Matrix Multiplication (TDPFP16PS)
    std::vector<uint16_t> fp16MatA(16 * 32, micant::amx::FloatToFp16(2.5f));
    std::vector<uint16_t> fp16MatB(16 * 32, micant::amx::FloatToFp16(4.0f));
    amxSub.loadTile(1, fp16MatA.data(), 64);
    amxSub.loadTile(2, fp16MatB.data(), 64);
    amxSub.loadTile(0, zeroTile.data(), 64);
    uint32_t fp16Lat = 0;
    int32_t fp16Stat = amxSub.multiplyFp16(0, 1, 2, &fp16Lat);
    TEST_ASSERT(fp16Stat == micant::amx::STATUS_SUCCESS, "multiplyFp16 must succeed");
    TEST_ASSERT(fp16Lat == 16, "FP16 systolic latency must be 16 ns");
    std::vector<float> fp16Dst(16 * 16, 0.0f);
    amxSub.storeTile(0, fp16Dst.data(), 64);
    // Expected element: 16 iterations * 2 elements per pair * (2.5 * 4.0) = 32 * 10.0 = 320.0f
    TEST_ASSERT(std::fabs(fp16Dst[0] - 320.0f) < 0.001f, "FP16 dot product element [0] must equal 320.0f");

    // Stage 11: Tile Release (TILERELEASE)
    int32_t relStat = amxSub.releaseTiles();
    TEST_ASSERT(relStat == micant::amx::STATUS_SUCCESS, "releaseTiles must succeed");
    TEST_ASSERT(amxSub.getCurrentConfig().paletteId == micant::amx::AMX_PALETTE_ID_NONE, "Palette must be unconfigured after release");
    const auto& releasedTile0 = amxSub.getTileRaw(0);
    TEST_ASSERT(releasedTile0.data[0][0] == 0, "Tile data must be zeroed upon release");

    // Stage 12: Execution Prevention in Unconfigured State (#UD)
    int32_t uncfgStat = amxSub.multiplyInt8(0, 1, 2, true, true);
    TEST_ASSERT(uncfgStat == micant::amx::STATUS_ILLEGAL_INSTRUCTION, "AMX multiply without configured palette must fail with STATUS_ILLEGAL_INSTRUCTION");

    // Stage 13: Arm SME Streaming SVE Mode Transition
    int32_t smeModeStat = amxSub.setSmeStreamingMode(true, true);
    TEST_ASSERT(smeModeStat == micant::amx::STATUS_SUCCESS, "setSmeStreamingMode must succeed");
    const auto& smeState = amxSub.getSmeState();
    TEST_ASSERT(smeState.streamingMode, "Arm SME Streaming Mode must be active");
    TEST_ASSERT(smeState.zaStorageEnabled, "Arm SME ZA Storage must be enabled");
    TEST_ASSERT(smeState.activeZaTiles == micant::amx::ARM_SME_MAX_TILES, "Active ZA tiles must be 8");

    // Stage 14: Arm SME Outer Product Accumulation (FMOPA)
    std::vector<float> smeVecA = {1.0f, 2.0f, 3.0f, 4.0f};
    std::vector<float> smeVecB = {5.0f, 6.0f, 7.0f, 8.0f};
    uint32_t smeLat = 0;
    int32_t smeOpStat = amxSub.smeOuterProduct(0, smeVecA.data(), smeVecB.data(), 4, &smeLat);
    TEST_ASSERT(smeOpStat == micant::amx::STATUS_SUCCESS, "smeOuterProduct must succeed");
    TEST_ASSERT(smeLat == 12, "SME outer product latency must be 12 ns");
    const auto& zaTile0 = amxSub.getTileRaw(0);
    const float* zaRow0 = reinterpret_cast<const float*>(zaTile0.data[0]);
    TEST_ASSERT(std::fabs(zaRow0[0] - 5.0f) < 0.001f, "ZA0[0][0] must be 1.0 * 5.0 = 5.0");
    TEST_ASSERT(std::fabs(zaRow0[3] - 8.0f) < 0.001f, "ZA0[0][3] must be 1.0 * 8.0 = 8.0");

    // Stage 15: Monotonic Telemetry Verification
    const auto& telem = amxSub.getTelemetry();
    TEST_ASSERT(telem.totalTileLoads >= 4, "totalTileLoads must be >= 4");
    TEST_ASSERT(telem.totalTileStores >= 4, "totalTileStores must be >= 4");
    TEST_ASSERT(telem.totalInt8Ops >= 1, "totalInt8Ops must be >= 1");
    TEST_ASSERT(telem.totalBf16Ops >= 1, "totalBf16Ops must be >= 1");
    TEST_ASSERT(telem.totalFp16Ops >= 1, "totalFp16Ops must be >= 1");
    TEST_ASSERT(telem.totalArmSmeOps >= 2, "totalArmSmeOps must be >= 2");
    TEST_ASSERT(telem.totalTilesReleased >= 1, "totalTilesReleased must be >= 1");

    // Stage 16: SCM Boot Driver Registration & Version Database
    auto& scm = micant::scm::ServiceControlManager::get();
    auto amxSvc = scm.getServiceRecord(L"intel_amx");
    TEST_ASSERT(amxSvc != nullptr, "intel_amx.sys must be registered in SCM");
    TEST_ASSERT(amxSvc->startType == micant::scm::SERVICE_BOOT_START, "intel_amx must be Boot start");

    auto smeSvc = scm.getServiceRecord(L"arm_sme");
    TEST_ASSERT(smeSvc != nullptr, "arm_sme.sys must be registered in SCM");
    TEST_ASSERT(smeSvc->startType == micant::scm::SERVICE_SYSTEM_START, "arm_sme must be System start");

    const auto* modAmx = micant::version::VersionDatabase::Instance().GetModuleInfo("intel_amx.sys");
    TEST_ASSERT(modAmx != nullptr, "intel_amx.sys must be registered in VersionDatabase");
    TEST_ASSERT(modAmx->stringTable.at("ProductVersion") == "10.0.26100.1", "intel_amx.sys version must match 10.0.26100.1");

    // C ABI Driver Exports
    uint32_t cMajor = 0, cMinor = 0, cBuild = 0;
    int32_t vStat = micant::amx::AmxGetVersion(&cMajor, &cMinor, &cBuild);
    TEST_ASSERT(vStat == micant::amx::STATUS_SUCCESS, "AmxGetVersion must succeed");
    TEST_ASSERT(cMajor == 10 && cBuild == 26100, "AMX version must match 10.0.26100");

    std::cout << "[TEST] Suite 173: Intel AMX & Arm SME Matrix Accelerator Subsystem PASSED.\n";
}

void Test_Bluetooth54_KernelPortDriver_Subsystem() {
    std::cout << "[TEST] Starting Suite 158: Bluetooth 5.4 & LE Audio Kernel Port Driver Subsystem...\n";

    // Stage 1: Subsystem Initialization & Local Radio BD_ADDR Verification
    bth::InitializeBluetoothKernelSubsystem();
    auto& bthSub = bth::TitanBluetoothSubsystem::Instance();
    TEST_ASSERT(bthSub.isInitialized() == true, "TitanBTH subsystem must be initialized");
    auto localAddr = bthSub.getRadioAddress();
    TEST_ASSERT(localAddr == bth::BdAddress::sovereignRadioDefault(), "Local BD_ADDR must match Sovereign default");
    TEST_ASSERT(localAddr.toString() == "00:1A:7D:DA:71:01", "Local BD_ADDR string format must be 00:1A:7D:DA:71:01");

    // Stage 2: HCI Version, LMP & Controller Identity Reporting
    TEST_ASSERT(bthSub.getHciVersion() == bth::BTH_VERSION_5_4, "HCI Version must be 0x0D (Bluetooth 5.4)");
    TEST_ASSERT(bthSub.getRadioName().find("Sovereign Bluetooth 5.4") != std::string::npos, "Radio name must identify as Sovereign Bluetooth 5.4");

    // Stage 3: Standard HCI Command Processing Engine
    // 3a. HCI Reset
    auto resetEvt = bthSub.executeHciCommand(bth::HCI_OP_RESET);
    TEST_ASSERT(resetEvt.size() >= 6, "HCI Reset event size must be at least 6 bytes");
    TEST_ASSERT(resetEvt[0] == bth::HCI_EVT_COMMAND_COMPLETE, "HCI Reset must return Command Complete event");
    TEST_ASSERT(resetEvt[5] == 0x00, "HCI Reset status must be 0 (Success)");

    // 3b. Read BD_ADDR
    auto bdAddrEvt = bthSub.executeHciCommand(bth::HCI_OP_READ_BD_ADDR);
    TEST_ASSERT(bdAddrEvt.size() >= 12, "Read BD_ADDR event size must be at least 12 bytes");
    TEST_ASSERT(bdAddrEvt[5] == 0x00, "Read BD_ADDR status must be Success");
    bth::BdAddress readAddr;
    std::memcpy(readAddr.bytes, &bdAddrEvt[6], 6);
    TEST_ASSERT(readAddr == localAddr, "HCI Read BD_ADDR returned address must match radio address");

    // 3c. Read Local Version Info
    auto verEvt = bthSub.executeHciCommand(bth::HCI_OP_READ_LOCAL_VERSION_INFO);
    TEST_ASSERT(verEvt.size() >= 14, "Read Local Version event size must be at least 14 bytes");
    TEST_ASSERT(verEvt[5] == 0x00, "Read Local Version status must be Success");
    TEST_ASSERT(verEvt[6] == bth::BTH_VERSION_5_4, "HCI Version in event payload must be 0x0D");

    // Stage 4: Scan Enable Modes (Inquiry & Page Scan)
    uint8_t scanParam = bth::BTH_SCAN_INQUIRY_AND_PAGE;
    auto scanEvt = bthSub.executeHciCommand(bth::HCI_OP_WRITE_SCAN_ENABLE, std::span<const uint8_t>(&scanParam, 1));
    TEST_ASSERT(scanEvt[0] == bth::HCI_EVT_COMMAND_COMPLETE, "Write Scan Enable must complete");
    TEST_ASSERT(bthSub.getScanMode() == bth::BTH_SCAN_INQUIRY_AND_PAGE, "Scan mode must be Inquiry and Page Scan");

    // Stage 5: L2CAP Signaling & Dynamic Channel Allocation (CID 0x0040+)
    uint16_t localCid = bthSub.openL2capChannel(0x0001, bth::L2CAP_PSM_RFCOMM, 0x0050);
    TEST_ASSERT(localCid >= bth::L2CAP_CID_DYNAMIC_START, "Allocated L2CAP CID must be in dynamic range (>= 0x0040)");
    const auto* chan = bthSub.getL2capChannel(localCid);
    TEST_ASSERT(chan != nullptr, "L2CAP channel lookup must succeed");
    TEST_ASSERT(chan->state == bth::L2capChannelState::Open, "L2CAP channel state must be Open");
    TEST_ASSERT(chan->psm == bth::L2CAP_PSM_RFCOMM, "L2CAP channel PSM must be RFCOMM (0x0003)");
    TEST_ASSERT(chan->mtu == 672, "L2CAP channel MTU must default to 672");

    // Stage 6: L2CAP Channel Teardown & Recycling
    bool closed = bthSub.closeL2capChannel(localCid);
    TEST_ASSERT(closed == true, "Closing L2CAP channel must succeed");
    TEST_ASSERT(bthSub.getL2capChannel(localCid) == nullptr, "Closed L2CAP channel must be removed");

    // Stage 7: RFCOMM Virtual Serial Port Creation (COM4 / Server Channel 1)
    uint16_t rfcommL2capCid = bthSub.openL2capChannel(0x0001, bth::L2CAP_PSM_RFCOMM, 0x0051);
    uint8_t chNum = bthSub.createRfcommPort(rfcommL2capCid, 1);
    TEST_ASSERT(chNum == 1, "RFCOMM server channel must be 1");
    const auto* rfPort = bthSub.getRfcommPort(chNum);
    TEST_ASSERT(rfPort != nullptr, "RFCOMM port lookup must succeed");
    TEST_ASSERT(rfPort->state == bth::RfcommPortState::Connected, "RFCOMM port state must be Connected");
    TEST_ASSERT(rfPort->baudRate == 115200, "RFCOMM baud rate must default to 115200 bps");
    TEST_ASSERT(rfPort->comPortName == L"COM4", "RFCOMM port name must be COM4");

    // Stage 8: RFCOMM Serial Data Streaming & Byte Accounting
    std::vector<uint8_t> testPayload = { 'A', 'T', 'Z', '\r', '\n' };
    size_t bytesSent = bthSub.transmitRfcommData(chNum, testPayload);
    TEST_ASSERT(bytesSent == testPayload.size(), "All RFCOMM payload bytes must be transmitted");
    rfPort = bthSub.getRfcommPort(chNum);
    TEST_ASSERT(rfPort->bytesSent == testPayload.size(), "RFCOMM port byte accounting must match payload size");

    // Stage 9: Bluetooth 5.4 LE Audio Connected Isochronous Stream (CIS) Configuration
    auto leAudio = bthSub.getLeAudioConfig();
    TEST_ASSERT(leAudio.active == true, "LE Audio stream must be active");
    TEST_ASSERT(leAudio.type == bth::LeAudioStreamType::UnicastCis, "LE Audio type must be Unicast CIS");
    TEST_ASSERT(leAudio.sampleRateHz == 48000, "LE Audio sample rate must be 48 kHz");
    TEST_ASSERT(leAudio.channels == 2, "LE Audio channel count must be stereo (2)");
    TEST_ASSERT(leAudio.isoHandle == 0x0010, "LE Audio ISO handle must be 0x0010");

    // Stage 10: LE Audio LC3 Codec Isochronous Frame Streaming
    std::vector<uint8_t> lc3Frame(120, 0xAA); // 120-byte 10ms LC3 audio frame
    bool isoSuccess = bthSub.transmitIsoStreamData(0x0010, lc3Frame);
    TEST_ASSERT(isoSuccess == true, "Transmission of LC3 isochronous audio frame must succeed");
    auto leAudioAfter = bthSub.getLeAudioConfig();
    TEST_ASSERT(leAudioAfter.framesTransmitted >= 1, "Frames transmitted counter must increment");
    TEST_ASSERT(leAudioAfter.bytesTransmitted >= 120, "Bytes transmitted counter must reflect LC3 frame size");

    // Stage 11: Bluetooth Bus Enumerator (bthenum.sys) Device Tree Queries
    auto devList = bthSub.getDiscoveredDevices();
    TEST_ASSERT(devList.size() >= 2, "At least 2 Bluetooth devices must be registered");
    bool foundKb = false;
    bool foundAudio = false;
    for (const auto& dev : devList) {
        if (dev.profile == bth::BthDeviceProfile::HidKeyboard) foundKb = true;
        if (dev.profile == bth::BthDeviceProfile::AudioLeLc3) foundAudio = true;
    }
    TEST_ASSERT(foundKb == true, "Titan Wireless Mechanical Keyboard (HID) must be enumerated");
    TEST_ASSERT(foundAudio == true, "PrismAudio Studio Auracast Headset (LE Audio) must be enumerated");

    // Stage 12: Dynamic Loader C ABI Exports Verification
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("bthport.sys", "BthPortInitialize") != nullptr, "bthport.sys BthPortInitialize must exist");
    TEST_ASSERT(ldr.getExport("bthport.sys", "BthPortSendHciCommand") != nullptr, "bthport.sys BthPortSendHciCommand must exist");
    TEST_ASSERT(ldr.getExport("bthport.sys", "BthPortOpenL2capChannel") != nullptr, "bthport.sys BthPortOpenL2capChannel must exist");
    TEST_ASSERT(ldr.getExport("bthport.sys", "BthPortCloseL2capChannel") != nullptr, "bthport.sys BthPortCloseL2capChannel must exist");
    TEST_ASSERT(ldr.getExport("bthport.sys", "BthPortCreateRfcommPort") != nullptr, "bthport.sys BthPortCreateRfcommPort must exist");
    TEST_ASSERT(ldr.getExport("bthusb.sys", "BthUsbInitialize") != nullptr, "bthusb.sys BthUsbInitialize must exist");
    TEST_ASSERT(ldr.getExport("bthenum.sys", "BthEnumEnumerateDevices") != nullptr, "bthenum.sys BthEnumEnumerateDevices must exist");
    TEST_ASSERT(ldr.getExport("rfcomm.sys", "BthPortCreateRfcommPort") != nullptr, "rfcomm.sys BthPortCreateRfcommPort must exist");

    // Stage 13: SCM Service Records & Version Database Verification
    auto bthPortSvc = scm::ServiceControlManager::get().getServiceRecord(L"bthport");
    TEST_ASSERT(bthPortSvc != nullptr, "bthport service record must exist in SCM");
    TEST_ASSERT(bthPortSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "bthport must be a kernel driver");
    TEST_ASSERT(bthPortSvc->startType == scm::SERVICE_BOOT_START, "bthport must have boot start type");

    auto bthUsbSvc = scm::ServiceControlManager::get().getServiceRecord(L"bthusb");
    TEST_ASSERT(bthUsbSvc != nullptr, "bthusb service record must exist in SCM");
    TEST_ASSERT(bthUsbSvc->startType == scm::SERVICE_SYSTEM_START, "bthusb must have system start type");

    auto rfcommSvc = scm::ServiceControlManager::get().getServiceRecord(L"rfcomm");
    TEST_ASSERT(rfcommSvc != nullptr, "rfcomm service record must exist in SCM");

    auto bthEnumSvc = scm::ServiceControlManager::get().getServiceRecord(L"bthenum");
    TEST_ASSERT(bthEnumSvc != nullptr, "bthenum service record must exist in SCM");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("bthport.sys") != nullptr, "bthport.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("bthusb.sys") != nullptr, "bthusb.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("rfcomm.sys") != nullptr, "rfcomm.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("bthenum.sys") != nullptr, "bthenum.sys must be registered in Version Database");

    // Stage 14: Telemetry Statistics Aggregation & C ABI Functionality
    auto telem = bthSub.getTelemetry();
    TEST_ASSERT(telem.hciCommandsSent >= 3, "Telemetry must record at least 3 HCI commands");
    TEST_ASSERT(telem.hciEventsReceived >= 3, "Telemetry must record at least 3 HCI events");
    TEST_ASSERT(telem.aclBytesSent > 0, "Telemetry must record ACL transmitted bytes");
    TEST_ASSERT(telem.isoBytesSent > 0, "Telemetry must record ISO transmitted bytes");

    uint32_t devCount = 0;
    int32_t enumRes = bth::BthEnumEnumerateDevices(&devCount);
    TEST_ASSERT(enumRes == 0 && devCount >= 2, "BthEnumEnumerateDevices C ABI must succeed and report devices");

    std::cout << "[TEST] Suite 158: Bluetooth 5.4 & LE Audio Kernel Port Driver Subsystem PASSED.\n";
}

void Test_DirectStorage12_BypassIO_Subsystem() {
    std::cout << "[TEST] Starting Suite 164: DirectStorage 1.2 / BypassIO & Storage Acceleration Subsystem...\n";

    // Stage 1: BypassIO Subsystem Initialization & Version Check
    bypassio::InitializeBypassIoSubsystem();
    auto& bpio = bypassio::TitanBypassIoSubsystem::Instance();
    TEST_ASSERT(bpio.isInitialized(), "BypassIO subsystem must be initialized");
    uint32_t ver = bypassio::BypassIoGetVersion();
    TEST_ASSERT(ver == 0x00010200, "BypassIO version must be 1.2 (0x00010200)");

    // Stage 2: Minifilter Stack Discovery & Default Compatibility
    auto filters = bpio.getFilters();
    TEST_ASSERT(filters.size() >= 3, "At least 3 clean-room minifilters must be registered");
    for (const auto& flt : filters) {
        TEST_ASSERT(flt.supportsBypassIo, "Default sovereign minifilters must support BypassIO");
    }

    // Stage 3: Simulated File Opening & Context Creation
    uint64_t fid = bpio.openFile("C:\\Games\\DirectStorageBench\\assets.pak", 8ULL * 1024 * 1024 * 1024);
    TEST_ASSERT(fid >= 1001, "Valid File ID must be assigned");
    const auto* ctx = bpio.getFileContext(fid);
    TEST_ASSERT(ctx != nullptr, "File context must be retrievable");
    TEST_ASSERT(!ctx->isBypassIoEnabled, "BypassIO must start disabled on new file handle");

    // Stage 4: FSCTL_MANAGE_BYPASS_IO Query Operation (FS_BPIO_OP_QUERY)
    bypassio::FS_BPIO_INPUT queryIn{ bypassio::FS_BPIO_OP_QUERY, bypassio::FS_BPIO_INFL_NONE, 0, 0 };
    bypassio::FS_BPIO_OUTPUT queryOut{};
    uint32_t qRes = bpio.manageBypassIo(fid, queryIn, queryOut);
    TEST_ASSERT(qRes == bypassio::FS_BPIO_SUCCESS, "FS_BPIO_OP_QUERY must succeed");
    TEST_ASSERT((queryOut.OutFlags & bypassio::FS_BPIO_OUTFL_VOLUME_STACK_BYPASS) != 0, "Volume stack bypass flag must be reported");

    // Stage 5: Incompatible Minifilter Rejection & Error Containment
    bpio.registerMinifilter("LegacyAntivirusFlt", 325000, false, "Minifilter does not implement BypassIO Fast-Path callback");
    bypassio::FS_BPIO_INPUT probeIn{ bypassio::FS_BPIO_OP_ENABLE, bypassio::FS_BPIO_INFL_VOLUME_STACK, 0, 0 };
    bypassio::FS_BPIO_OUTPUT probeOut{};
    uint32_t probeRes = bpio.manageBypassIo(fid, probeIn, probeOut);
    TEST_ASSERT(probeRes == bypassio::FS_BPIO_STATUS_FILTER_INCOMPATIBLE, "BypassIO enable must fail when incompatible filter is present");
    TEST_ASSERT(probeOut.IncompatibleFilterCount == 1, "Incompatible filter count must be 1");
    TEST_ASSERT(std::string(probeOut.IncompatibleDriverName) == "LegacyAntivirusFlt", "Incompatible driver name must match");
    bpio.unregisterMinifilter("LegacyAntivirusFlt");

    // Stage 6: FSCTL_MANAGE_BYPASS_IO Enable Operation (FS_BPIO_OP_ENABLE)
    bypassio::FS_BPIO_INPUT enableIn{ bypassio::FS_BPIO_OP_ENABLE, bypassio::FS_BPIO_INFL_VOLUME_STACK | bypassio::FS_BPIO_INFL_DMA_VRAM_TARGET, 0, 0 };
    bypassio::FS_BPIO_OUTPUT enableOut{};
    uint32_t enableRes = bpio.manageBypassIo(fid, enableIn, enableOut);
    TEST_ASSERT(enableRes == bypassio::FS_BPIO_SUCCESS, "FS_BPIO_OP_ENABLE must succeed after removing incompatible filter");
    TEST_ASSERT((enableOut.OutFlags & bypassio::FS_BPIO_OUTFL_GPU_DMA_ACTIVE) != 0, "GPU DMA flag must be reported");
    ctx = bpio.getFileContext(fid);
    TEST_ASSERT(ctx->isBypassIoEnabled, "BypassIO must now be enabled on file object");

    // Stage 7: Fast-Path Read Execution Bypassing Filesystem Filter Stack
    std::vector<uint8_t> readBuf(65536);
    uint32_t fastReadLat = 0;
    bool fastReadOk = bpio.fastRead(fid, 0, static_cast<uint32_t>(readBuf.size()), readBuf.data(), &fastReadLat);
    TEST_ASSERT(fastReadOk, "Fast-path read must succeed");
    TEST_ASSERT(readBuf[0] == 0x5A, "Direct NVMe payload must be returned");

    // Stage 8: Sub-25 Microsecond Latency Verification
    TEST_ASSERT(fastReadLat <= 25, "Fast-path read latency must be <= 25 microseconds");

    // Stage 9: Direct NVMe-to-VRAM DMA Transfer
    uint32_t dmaLat = 0;
    uint64_t gpuVramAddress = 0x200000000ULL; // 64KB aligned GPU Virtual Address (VRAM BAR aperture)
    bool dmaOk = bpio.transferNvmeToVram(fid, 65536, 131072, gpuVramAddress, &dmaLat);
    TEST_ASSERT(dmaOk, "Direct NVMe-to-VRAM DMA transfer must succeed");
    TEST_ASSERT(dmaLat <= 25, "NVMe-to-VRAM DMA latency must be <= 25 microseconds");

    // Stage 10: Misaligned GPU VRAM DMA Rejection
    uint32_t failLat = 0;
    bool misalignedOk = bpio.transferNvmeToVram(fid, 0, 4096, 0x200000123ULL, &failLat);
    TEST_ASSERT(!misalignedOk, "Misaligned GPU VRAM address must be rejected by DMA engine");

    // Stage 11: Volume Stack Pause Operation (FS_BPIO_OP_VOLUME_STACK_PAUSE)
    NTSTATUS pauseSt = bypassio::BypassIoPauseVolume();
    TEST_ASSERT(pauseSt == STATUS_SUCCESS, "BypassIoPauseVolume must succeed");

    // Stage 12: Rejection of BypassIO During Volume Stack Pause
    uint32_t pausedLat = 0;
    bool pausedReadOk = bpio.fastRead(fid, 0, 4096, readBuf.data(), &pausedLat);
    TEST_ASSERT(!pausedReadOk, "Fast read must be rejected while volume stack is paused");

    // Stage 13: Volume Stack Resume Operation (FS_BPIO_OP_VOLUME_STACK_RESUME)
    NTSTATUS resumeSt = bypassio::BypassIoResumeVolume();
    TEST_ASSERT(resumeSt == STATUS_SUCCESS, "BypassIoResumeVolume must succeed");
    bool resumedReadOk = bpio.fastRead(fid, 0, 4096, readBuf.data(), &pausedLat);
    TEST_ASSERT(resumedReadOk, "Fast read must succeed after volume stack resume");

    // Stage 14: GDeflate 1.2 Lossless Compression & Magic Header Validation
    std::vector<uint8_t> rawAsset(256 * 1024);
    for (size_t i = 0; i < rawAsset.size(); ++i) {
        rawAsset[i] = static_cast<uint8_t>((i / 16) & 0xFF);
    }
    auto gdefData = bypassio::GDeflateCodec::Compress(rawAsset.data(), rawAsset.size());
    TEST_ASSERT(gdefData.size() >= sizeof(bypassio::GDeflateHeader), "Compressed GDeflate stream must contain header");
    const auto* ghdr = reinterpret_cast<const bypassio::GDeflateHeader*>(gdefData.data());
    TEST_ASSERT(ghdr->magic == bypassio::GDEFLATE_MAGIC, "GDeflate magic must match 0x44474447");
    TEST_ASSERT(ghdr->uncompressedSize == rawAsset.size(), "Uncompressed size in header must match source size");
    TEST_ASSERT(gdefData.size() < rawAsset.size(), "GDeflate must achieve compression on structured data");

    // Stage 15: Bit-Exact GDeflate Decompression Verification
    std::vector<uint8_t> decodedAsset(rawAsset.size());
    size_t actualDecodedSize = 0;
    bool decompOk = bypassio::GDeflateCodec::Decompress(gdefData.data(), gdefData.size(),
                                                        decodedAsset.data(), decodedAsset.size(), &actualDecodedSize);
    TEST_ASSERT(decompOk, "GDeflate decompression must succeed");
    TEST_ASSERT(actualDecodedSize == rawAsset.size(), "Decoded size must equal original size");
    TEST_ASSERT(std::memcmp(rawAsset.data(), decodedAsset.data(), rawAsset.size()) == 0,
                "Decompressed data must be a bit-exact match with original uncompressed asset");

    // Stage 16: Storage QoS (storqos.sys), Driver SCM & Dynamic Loader Registration
    auto qosTelem = bpio.getQosTelemetry();
    TEST_ASSERT(qosTelem.currentBandwidthMBps > 0, "QoS bandwidth telemetry must be active");
    TEST_ASSERT(qosTelem.avgLatencyUs <= 25, "QoS average latency target must be sub-25 microseconds");

    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("bypassio.sys", "BypassIoManageOperation") != nullptr, "BypassIoManageOperation export must exist");
    TEST_ASSERT(ldr.getExport("bypassio.sys", "BypassIoProcessFastRead") != nullptr, "BypassIoProcessFastRead export must exist");
    TEST_ASSERT(ldr.getExport("storqos.sys", "DirectStorageKernelDecompress") != nullptr, "DirectStorageKernelDecompress export must exist");
    TEST_ASSERT(ldr.getExport("storqos.sys", "DirectStorageTransferNvmeToVram") != nullptr, "DirectStorageTransferNvmeToVram export must exist");

    auto bpioSvc = scm::ServiceControlManager::get().getServiceRecord(L"bypassio");
    TEST_ASSERT(bpioSvc != nullptr, "bypassio service record must exist in SCM");
    TEST_ASSERT(bpioSvc->startType == scm::SERVICE_BOOT_START, "bypassio must have boot start type");

    auto storqosSvc = scm::ServiceControlManager::get().getServiceRecord(L"storqos");
    TEST_ASSERT(storqosSvc != nullptr, "storqos service record must exist in SCM");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("bypassio.sys") != nullptr, "bypassio.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("storqos.sys") != nullptr, "storqos.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 164: DirectStorage 1.2 / BypassIO & Storage Acceleration Subsystem PASSED.\n";
}

void Test_IntelCET_HardwareEnforcedStackProtection_Subsystem() {
    std::cout << "[TEST] Starting Suite 169: Intel CET & Hardware-Enforced Stack Protection Subsystem...\n";

    // Stage 1: Subsystem Registration & Initialization
    micant::cet::RegisterCetSubsystem();
    auto& cetSub = micant::cet::TitanCetSubsystem::get();
    bool initOk = cetSub.initialize(micant::cet::CetEnforcementMode::FullEnforced);
    TEST_ASSERT(initOk, "TitanCetSubsystem initialization must succeed");
    TEST_ASSERT(cetSub.isInitialized(), "TitanCetSubsystem must report initialized state");

    // Stage 2: Hardware Capabilities Check
    auto caps = cetSub.getCapabilities();
    TEST_ASSERT(caps.hasShadowStack == true, "Intel CET Shadow Stack capability must be present");
    TEST_ASSERT(caps.hasIbt == true, "Indirect Branch Tracking (IBT) capability must be present");
    TEST_ASSERT(caps.hasWrss == true, "WRSS/WRUSS shadow stack write instructions must be supported");
    TEST_ASSERT(caps.hasUserModeCet == true, "User Mode CET (Ring 3) must be supported");
    TEST_ASSERT(caps.hasSupervisorCet == true, "Supervisor Mode CET (Ring 0) must be supported");

    // Stage 3: Architectural MSR State Verification
    uint64_t sCet = cetSub.getMsrSupervisorCet();
    TEST_ASSERT((sCet & micant::cet::CET_SH_STK_EN) != 0, "MSR_IA32_S_CET must have SH_STK_EN enabled");
    TEST_ASSERT((sCet & micant::cet::CET_WR_SHSTK_EN) != 0, "MSR_IA32_S_CET must have WR_SHSTK_EN enabled");
    TEST_ASSERT((sCet & micant::cet::CET_ENDBR_EN) != 0, "MSR_IA32_S_CET must have ENDBR_EN enabled");
    uint64_t uCet = cetSub.getMsrUserCet();
    TEST_ASSERT((uCet & micant::cet::CET_SH_STK_EN) != 0, "MSR_IA32_U_CET must have SH_STK_EN enabled");

    // Stage 4: Kernel Shadow Stack Allocation (Ring 0)
    uint32_t kStackId = cetSub.allocateShadowStack(4, 100, true);
    TEST_ASSERT(kStackId > 0, "Allocation of Ring 0 kernel shadow stack must succeed");

    // Stage 5: Userland Shadow Stack Allocation (Ring 3)
    uint32_t uStackId = cetSub.allocateShadowStack(1000, 1001, false);
    TEST_ASSERT(uStackId > 0, "Allocation of Ring 3 userland shadow stack must succeed");
    TEST_ASSERT(uStackId != kStackId, "Stack IDs must be unique across allocations");

    // Stage 6: Restore Token and Busy Bit Initialization
    auto stacks = cetSub.getActiveShadowStacks();
    TEST_ASSERT(stacks.size() >= 2, "Active shadow stacks count must be at least 2");
    auto kDescIt = std::find_if(stacks.begin(), stacks.end(), [kStackId](const auto& s){ return s.stackId == kStackId; });
    TEST_ASSERT(kDescIt != stacks.end(), "Kernel stack descriptor must be found");
    TEST_ASSERT(kDescIt->isKernelMode == true, "Descriptor must identify as kernel mode");
    TEST_ASSERT((kDescIt->restoreToken & 0x01ULL) != 0, "Restore token busy bit must be set on active stack");

    // Stage 7: Hardware Legitimate Call/Ret Sequence
    uint64_t funcReturn1 = 0x00007FF710001234ULL;
    bool callOk = cetSub.simulateCall(kStackId, funcReturn1);
    TEST_ASSERT(callOk, "SimulateCall pushing to shadow stack must succeed");
    uint32_t retStatus = cetSub.simulateRet(kStackId, funcReturn1, 0x000000000019F000ULL);
    TEST_ASSERT(retStatus == 0, "SimulateRet with matching return IP must return STATUS_SUCCESS");

    // Stage 8: Nested Call Depth & Frame Unwinding
    uint64_t nest1 = 0x00007FF710002000ULL;
    uint64_t nest2 = 0x00007FF710003000ULL;
    uint64_t nest3 = 0x00007FF710004000ULL;
    cetSub.simulateCall(uStackId, nest1);
    cetSub.simulateCall(uStackId, nest2);
    cetSub.simulateCall(uStackId, nest3);
    TEST_ASSERT(cetSub.simulateRet(uStackId, nest3) == 0, "Unwinding nest3 must succeed");
    TEST_ASSERT(cetSub.simulateRet(uStackId, nest2) == 0, "Unwinding nest2 must succeed");
    TEST_ASSERT(cetSub.simulateRet(uStackId, nest1) == 0, "Unwinding nest1 must succeed");

    // Stage 9: Return-Oriented Programming (ROP) Stack Pivot Attack Interception
    uint64_t legitimateReturn = 0x00007FF740005000ULL;
    uint64_t maliciousGadgetReturn = 0x00007FF7DEADBEEFULL;
    cetSub.simulateCall(kStackId, legitimateReturn);
    uint32_t ropTrapStatus = cetSub.simulateRet(kStackId, maliciousGadgetReturn, 0x000000000019F100ULL);
    TEST_ASSERT(ropTrapStatus == micant::cet::STATUS_CONTROL_STACK_VIOLATION,
        "ROP stack pivot must trigger STATUS_CONTROL_STACK_VIOLATION (0xC0000428)");

    // Stage 10: Control Protection Exception (#CP Vector 21) Error Code Verification
    auto violations = cetSub.getViolations();
    TEST_ASSERT(!violations.empty(), "A CET violation record must be logged");
    const auto& lastV = violations.back();
    TEST_ASSERT(lastV.errorCode == micant::cet::CP_FAULT_NEAR_RET,
        "Violation error code must be CP_FAULT_NEAR_RET (0x1)");
    TEST_ASSERT(lastV.expectedAddress == legitimateReturn, "Expected address must match shadow stack entry");
    TEST_ASSERT(lastV.actualAddress == maliciousGadgetReturn, "Actual address must reflect attacker gadget");

    // Stage 11: Indirect Branch Tracking (IBT) Legitimate Call with ENDBR64
    uint64_t validJmpTarget = 0x00007FF750001000ULL;
    uint32_t ibtOkStatus = cetSub.verifyIndirectBranch(1000, 1001, validJmpTarget, micant::cet::ENDBR64_OPCODE);
    TEST_ASSERT(ibtOkStatus == 0, "Indirect branch with valid ENDBR64 must succeed");

    // Stage 12: Jump-Oriented Programming (JOP) Call Missing ENDBR64
    uint64_t invalidJmpTarget = 0x00007FF750002000ULL;
    uint32_t missingEndbrOpcode = 0x90909090;
    uint32_t jopTrapStatus = cetSub.verifyIndirectBranch(1000, 1001, invalidJmpTarget, missingEndbrOpcode);
    TEST_ASSERT(jopTrapStatus == micant::cet::STATUS_CONTROL_STACK_VIOLATION,
        "JOP indirect jump missing ENDBR64 must trigger STATUS_CONTROL_STACK_VIOLATION");
    auto violationsAfterJop = cetSub.getViolations();
    TEST_ASSERT(violationsAfterJop.back().errorCode == micant::cet::CP_FAULT_ENDBR,
        "Violation error code must be CP_FAULT_ENDBR (0x3)");

    // Stage 13: Shadow Stack Switching (RSTORSSP / Token Verification)
    uint32_t newStackId = cetSub.allocateShadowStack(4, 101, true);
    bool switchOk = cetSub.switchShadowStack(kStackId, newStackId);
    TEST_ASSERT(switchOk, "Valid shadow stack switch with busy restore token must succeed");

    // Stage 14: Dynamic Loader C ABI Symbol Resolution
    auto& ldr = micant::ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("kshadowstack.sys", "CetInitialize") != nullptr, "kshadowstack.sys!CetInitialize must be exported");
    TEST_ASSERT(ldr.getExport("kshadowstack.sys", "CetGetCapabilities") != nullptr, "kshadowstack.sys!CetGetCapabilities must be exported");
    TEST_ASSERT(ldr.getExport("kshadowstack.sys", "CetAllocateShadowStack") != nullptr, "kshadowstack.sys!CetAllocateShadowStack must be exported");
    TEST_ASSERT(ldr.getExport("kshadowstack.sys", "CetSimulateCall") != nullptr, "kshadowstack.sys!CetSimulateCall must be exported");
    TEST_ASSERT(ldr.getExport("kshadowstack.sys", "CetSimulateRet") != nullptr, "kshadowstack.sys!CetSimulateRet must be exported");
    TEST_ASSERT(ldr.getExport("kshadowstack.sys", "CetVerifyIndirectBranch") != nullptr, "kshadowstack.sys!CetVerifyIndirectBranch must be exported");
    TEST_ASSERT(ldr.getExport("kshadowstack.sys", "CetGetTelemetry") != nullptr, "kshadowstack.sys!CetGetTelemetry must be exported");
    TEST_ASSERT(ldr.getExport("cet.sys", "CetInitialize") != nullptr, "cet.sys!CetInitialize must be exported");

    // Stage 15: Service Control Manager (SCM) Registration
    auto kssSvc = micant::scm::ServiceControlManager::get().getServiceRecord(L"kshadowstack");
    TEST_ASSERT(kssSvc != nullptr, "kshadowstack service record must exist in SCM");
    TEST_ASSERT(kssSvc->serviceType == micant::scm::SERVICE_KERNEL_DRIVER, "kshadowstack must be registered as SERVICE_KERNEL_DRIVER");
    TEST_ASSERT(kssSvc->startType == micant::scm::SERVICE_BOOT_START, "kshadowstack must be configured as SERVICE_BOOT_START");
    auto cetSvc = micant::scm::ServiceControlManager::get().getServiceRecord(L"cet");
    TEST_ASSERT(cetSvc != nullptr, "cet service record must exist in SCM");
    TEST_ASSERT(cetSvc->startType == micant::scm::SERVICE_SYSTEM_START, "cet must be configured as SERVICE_SYSTEM_START");

    // Stage 16: Version Database Module Registration
    const auto* modKss = micant::version::VersionDatabase::Instance().GetModuleInfo("kshadowstack.sys");
    TEST_ASSERT(modKss != nullptr, "kshadowstack.sys must be registered in VersionDatabase");
    TEST_ASSERT(modKss->stringTable.at("ProductVersion") == "10.0.26100.1", "kshadowstack.sys version must match 10.0.26100.1");

    // Clean up allocated stacks
    cetSub.freeShadowStack(kStackId);
    cetSub.freeShadowStack(uStackId);
    cetSub.freeShadowStack(newStackId);

    std::cout << "[TEST] Suite 169: Intel CET & Hardware-Enforced Stack Protection Subsystem PASSED.\n";
}

void Test_ComputeExpressLink_CXL_HeterogeneousMemory_Subsystem() {
    std::cout << "[TEST] Starting Suite 162: Compute Express Link (CXL 2.0 / 3.1) & Heterogeneous Memory Fabric...\n";

    // Initialize Subsystem & Register Components
    pci::InitializePciSubsystem();
    cxl::InitializeCxlSubsystem();
    auto& cxlSub = cxl::TitanCxlSubsystem::Instance();
    TEST_ASSERT(cxlSub.isInitialized() == true, "TitanCXL subsystem must be initialized");

    // Stage 1: CXL Specification Version Verification (Revision 3.1)
    uint32_t cxlMaj = 0, cxlMin = 0;
    cxlSub.getVersion(&cxlMaj, &cxlMin);
    TEST_ASSERT(cxlMaj == 3 && cxlMin == 1, "CXL specification version must be 3.1");

    // Stage 2: CXL Host Bridge & Root Port on PCIe Bus 0 (00:09.0)
    auto pciDev = pci::TitanPciSubsystem::Instance().findDevice(pci::PciAddress(0, 9, 0));
    TEST_ASSERT(pciDev != nullptr, "TitanCXL Host Bridge must be registered at 00:09.0");
    TEST_ASSERT(pciDev->getVendorId() == 0x1E98, "CXL Host Bridge Vendor ID must be 0x1E98 (CXL Consortium)");
    TEST_ASSERT(pciDev->getDeviceId() == 0x0001, "CXL Host Bridge Device ID must be 0x0001 (CXL 3.1 Host Bridge)");
    TEST_ASSERT(pciDev->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Bridge), "Base class must be Bridge (0x06)");
    TEST_ASSERT(pciDev->getSubClass() == 0x04, "Subclass must be PCI-to-PCI Bridge (0x04)");

    // Stage 3: CXL Host Bridge BAR0 MMIO Component Registers
    const auto& bar0 = pciDev->getBar(0);
    TEST_ASSERT(bar0.type == pci::PciBarType::Memory64, "BAR0 must be 64-bit MMIO");
    TEST_ASSERT(bar0.size == 64 * 1024, "BAR0 Component Register size must be 64 KB");

    // Stage 4: CXL Bus 4 Endpoint Enumeration & Type Identification
    auto memDev = pci::TitanPciSubsystem::Instance().findDevice(pci::PciAddress(4, 0, 0));
    TEST_ASSERT(memDev != nullptr, "TitanCXL Type 3 Memory Expander must be registered at 04:00.0");
    TEST_ASSERT(memDev->getVendorId() == 0x1E98, "Type 3 Memory Expander Vendor ID must be 0x1E98");
    TEST_ASSERT(memDev->getDeviceId() == 0x0010, "Type 3 Memory Expander Device ID must be 0x0010");
    TEST_ASSERT(memDev->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Memory), "Base class must be Memory (0x05)");

    auto accDev = pci::TitanPciSubsystem::Instance().findDevice(pci::PciAddress(4, 1, 0));
    TEST_ASSERT(accDev != nullptr, "TitanCXL Type 2 Heterogeneous Accelerator must be registered at 04:01.0");
    TEST_ASSERT(accDev->getVendorId() == 0x1E98, "Type 2 Accelerator Vendor ID must be 0x1E98");
    TEST_ASSERT(accDev->getDeviceId() == 0x0020, "Type 2 Accelerator Device ID must be 0x0020");
    TEST_ASSERT(accDev->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Accelerator), "Base class must be Accelerator (0x12)");

    // Stage 5: CXL Sub-Protocols Negotiation
    const auto* dev1Info = cxlSub.getDevice(1);
    TEST_ASSERT(dev1Info != nullptr, "Device 1 lookup must succeed");
    TEST_ASSERT(dev1Info->type == cxl::CxlDeviceType::Type3_MemoryExpander, "Device 1 must be Type 3 Memory Expander");
    TEST_ASSERT(dev1Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlIo), "Device 1 must support CXL.io");
    TEST_ASSERT(dev1Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlMem), "Device 1 must support CXL.mem");
    TEST_ASSERT(!(dev1Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlCache)), "Device 1 Type 3 does not use CXL.cache");

    const auto* dev2Info = cxlSub.getDevice(2);
    TEST_ASSERT(dev2Info != nullptr, "Device 2 lookup must succeed");
    TEST_ASSERT(dev2Info->type == cxl::CxlDeviceType::Type2_DenseAccelerator, "Device 2 must be Type 2 Dense Accelerator");
    TEST_ASSERT(dev2Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlIo), "Device 2 must support CXL.io");
    TEST_ASSERT(dev2Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlCache), "Device 2 must support CXL.cache");
    TEST_ASSERT(dev2Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlMem), "Device 2 must support CXL.mem");

    // Stage 6: Type 3 Memory Expander BAR Allocation (BAR2 128GB Memory Aperture)
    const auto& memBar0 = memDev->getBar(0);
    TEST_ASSERT(memBar0.size == 64 * 1024, "Type 3 BAR0 MMIO size must be 64 KB");
    const auto& memBar2 = memDev->getBar(2);
    TEST_ASSERT(memBar2.type == pci::PciBarType::Memory64, "BAR2 must be 64-bit MMIO");
    TEST_ASSERT(memBar2.prefetchable == true, "BAR2 CXL.mem aperture must be prefetchable");
    TEST_ASSERT(memBar2.size == 128ULL * 1024 * 1024 * 1024, "BAR2 CXL.mem capacity must be 128 GB");

    // Stage 7: HDM Decoder 0 Configuration & SPA Mapping
    TEST_ASSERT(!dev1Info->decoders.empty(), "Device 1 must have at least one HDM decoder");
    const auto& dec0 = dev1Info->decoders[0];
    TEST_ASSERT(dec0.decoderIndex == 0, "Decoder index must be 0");
    TEST_ASSERT(dec0.baseSpa == 0x1000000000ULL, "Base SPA must be 64 GB physical address boundary (0x10_0000_0000)");
    TEST_ASSERT(dec0.sizeBytes == 128ULL * 1024 * 1024 * 1024, "Decoder 0 size must match 128 GB capacity");
    TEST_ASSERT(dec0.granularity == cxl::CxlInterleaveGranularity::Granularity256B, "Interleave granularity must be 256 bytes");
    TEST_ASSERT(dec0.ways == cxl::CxlInterleaveWays::Way1, "Interleave ways must be 1-way (single device)");
    TEST_ASSERT(dec0.isCommitted == true, "Decoder 0 must be committed to hardware");

    // Stage 8: Type 2 Accelerator Coherent Memory Aperture (64GB HBM)
    TEST_ASSERT(!dev2Info->decoders.empty(), "Device 2 must have HDM decoder");
    const auto& dec1 = dev2Info->decoders[0];
    TEST_ASSERT(dec1.baseSpa == 0x3000000000ULL, "Base SPA must be 192 GB boundary (0x30_0000_0000)");
    TEST_ASSERT(dec1.sizeBytes == 64ULL * 1024 * 1024 * 1024, "Decoder size must match 64 GB HBM");
    TEST_ASSERT(dec1.granularity == cxl::CxlInterleaveGranularity::Granularity512B, "Granularity must be 512 bytes");
    TEST_ASSERT(dec1.isCommitted == true, "Decoder must be committed");

    // Stage 9: CXL Mailbox Command Execution: IDENTIFY_MEMORY_DEVICE (0x4000)
    std::vector<uint8_t> identOut;
    NTSTATUS idSt = cxlSub.sendMailboxCommand(1, cxl::CXL_MBOX_OP_IDENTIFY_MEMORY_DEVICE, {}, identOut);
    TEST_ASSERT(idSt == STATUS_SUCCESS, "Identify Memory Device mailbox command must succeed");
    TEST_ASSERT(identOut.size() >= 15, "Identify payload size must be >= 15 bytes");
    std::string identStr(reinterpret_cast<char*>(identOut.data()), 15);
    TEST_ASSERT(identStr == "TITAN-CXL-REV31", "Identify string must match TITAN-CXL-REV31");

    // Stage 10: CXL Mailbox S.M.A.R.T. Health Telemetry (0x4001)
    std::vector<uint8_t> smartOut;
    NTSTATUS smSt = cxlSub.sendMailboxCommand(1, cxl::CXL_MBOX_OP_GET_SMART_HEALTH, {}, smartOut);
    TEST_ASSERT(smSt == STATUS_SUCCESS, "Get S.M.A.R.T. Health mailbox command must succeed");
    TEST_ASSERT(smartOut.size() == sizeof(cxl::CxlSmartHealthInfo), "S.M.A.R.T. payload size must match struct size");
    const auto* smart = reinterpret_cast<const cxl::CxlSmartHealthInfo*>(smartOut.data());
    TEST_ASSERT(smart->healthStatus == 0, "Health status must be normal (0)");
    TEST_ASSERT(smart->mediaStatus == 0, "Media status must be normal (0)");
    TEST_ASSERT(smart->temperatureCelsius > 20.0f && smart->temperatureCelsius < 80.0f, "Temperature must be within operating range");
    TEST_ASSERT(smart->dirtyShutdownCount == 0, "Dirty shutdown count must be 0");

    // Stage 11: Address Poisoning & Fault Isolation (INJECT_POISON, GET_POISON_LIST, CLEAR_POISON)
    uint64_t targetDpa = 0x10008000ULL;
    std::vector<uint8_t> injPayload(sizeof(targetDpa));
    std::memcpy(injPayload.data(), &targetDpa, sizeof(targetDpa));
    NTSTATUS injSt = cxlSub.sendMailboxCommand(1, cxl::CXL_MBOX_OP_INJECT_POISON, injPayload, identOut);
    TEST_ASSERT(injSt == STATUS_SUCCESS, "Inject Poison mailbox command must succeed");

    std::vector<uint8_t> poisonOut;
    NTSTATUS plistSt = cxlSub.sendMailboxCommand(1, cxl::CXL_MBOX_OP_GET_POISON_LIST, {}, poisonOut);
    TEST_ASSERT(plistSt == STATUS_SUCCESS, "Get Poison List mailbox command must succeed");
    uint32_t poisonCount = 0;
    std::memcpy(&poisonCount, poisonOut.data(), sizeof(poisonCount));
    TEST_ASSERT(poisonCount == 1, "Poison list must contain exactly 1 entry");

    const auto* prec = reinterpret_cast<const cxl::CxlPoisonRecord*>(poisonOut.data() + sizeof(uint32_t));
    TEST_ASSERT(prec->devicePhysicalAddress == targetDpa, "Poisoned DPA must match injected address");
    TEST_ASSERT(prec->lengthBytes == 64, "Poisoned cache line length must be 64 bytes");

    // Clear poison
    NTSTATUS clrSt = cxlSub.sendMailboxCommand(1, cxl::CXL_MBOX_OP_CLEAR_POISON, injPayload, identOut);
    TEST_ASSERT(clrSt == STATUS_SUCCESS, "Clear Poison mailbox command must succeed");
    auto clearedList = cxlSub.getPoisonList(1);
    TEST_ASSERT(clearedList.empty(), "Poison list must be empty after clearing");

    // Stage 12: Dynamic Memory Tiering (DMT) & NUMA Node 1 Expansion
    const auto& tiering = cxlSub.getNumaTieringInfo();
    TEST_ASSERT(tiering.tierId == 1, "Tier ID must be 1 (Far Memory)");
    TEST_ASSERT(tiering.numaNodeId == 1, "NUMA node must be Node 1");
    TEST_ASSERT(tiering.totalCapacityBytes == 128ULL * 1024 * 1024 * 1024, "Total capacity must be 128 GB");
    TEST_ASSERT(tiering.readLatencyNs == 140, "Far Memory read latency must be 140 ns");
    TEST_ASSERT(tiering.writeLatencyNs == 150, "Far Memory write latency must be 150 ns");
    TEST_ASSERT(tiering.peakBandwidthGBps >= 60.0f, "Peak bandwidth must be >= 60 GB/s (PCIe 5.0 x16)");

    // Stage 13: DMT Page Migration Simulation (Demote to Far Memory & Promote to Near Memory)
    uint64_t initialAllocated = tiering.allocatedBytes;
    uint64_t initialMigrated = tiering.pagesMigratedToFar;
    bool migOk = cxlSub.migratePages(1, 1024, true); // Demote 1024 pages (4 MB)
    TEST_ASSERT(migOk == true, "Page migration to far memory must succeed");
    const auto& updatedTiering = cxlSub.getNumaTieringInfo();
    TEST_ASSERT(updatedTiering.allocatedBytes == initialAllocated + (1024 * 4096ULL), "Allocated capacity must increase by 4 MB");
    TEST_ASSERT(updatedTiering.pagesMigratedToFar == initialMigrated + 1024, "Pages migrated counter must increment by 1024");

    uint64_t initialPromoted = updatedTiering.pagesPromotedToNear;
    bool promOk = cxlSub.migratePages(1, 512, false); // Promote 512 pages (2 MB)
    TEST_ASSERT(promOk == true, "Page promotion to near memory must succeed");
    const auto& finalTiering = cxlSub.getNumaTieringInfo();
    TEST_ASSERT(finalTiering.pagesPromotedToNear == initialPromoted + 512, "Pages promoted counter must increment by 512");

    // Stage 14: CXL Fabric Telemetry Accounting
    const auto& telem = cxlSub.getTelemetry();
    TEST_ASSERT(telem.activeDevices >= 2, "Active CXL devices counter must be >= 2");
    TEST_ASSERT(telem.totalCxlReadTransactions > 0, "CXL read transactions counter must be positive");
    TEST_ASSERT(telem.totalCxlWriteTransactions > 0, "CXL write transactions counter must be positive");
    TEST_ASSERT(telem.totalFlitsTransferred > 0, "Flits transferred counter must be positive");
    TEST_ASSERT(telem.totalMailboxCommandsExecuted >= 4, "Mailbox commands executed counter must be >= 4");
    TEST_ASSERT(telem.currentFabricThroughputGBps > 0.0f, "Current fabric throughput must be positive");

    // Stage 15: Dynamic Loader C ABI Driver Exports (cxlhost.sys, cxlmem.sys, cxlbus.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("cxlhost.sys", "CxlHostInitialize") != nullptr, "cxlhost.sys CxlHostInitialize must exist");
    TEST_ASSERT(ldr.getExport("cxlhost.sys", "CxlHostGetVersion") != nullptr, "cxlhost.sys CxlHostGetVersion must exist");
    TEST_ASSERT(ldr.getExport("cxlhost.sys", "CxlHostEnumerateBridges") != nullptr, "cxlhost.sys CxlHostEnumerateBridges must exist");

    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemGetDeviceInfo") != nullptr, "cxlmem.sys CxlMemGetDeviceInfo must exist");
    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemConfigureHdmDecoder") != nullptr, "cxlmem.sys CxlMemConfigureHdmDecoder must exist");
    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemGetSmartHealth") != nullptr, "cxlmem.sys CxlMemGetSmartHealth must exist");
    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemQueryPoisonList") != nullptr, "cxlmem.sys CxlMemQueryPoisonList must exist");
    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemInjectPoison") != nullptr, "cxlmem.sys CxlMemInjectPoison must exist");
    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemMigratePages") != nullptr, "cxlmem.sys CxlMemMigratePages must exist");

    TEST_ASSERT(ldr.getExport("cxlbus.sys", "CxlBusRegisterDevice") != nullptr, "cxlbus.sys CxlBusRegisterDevice must exist");
    TEST_ASSERT(ldr.getExport("cxlbus.sys", "CxlBusGetDeviceCount") != nullptr, "cxlbus.sys CxlBusGetDeviceCount must exist");
    TEST_ASSERT(ldr.getExport("cxlbus.sys", "CxlBusSendMailboxCommand") != nullptr, "cxlbus.sys CxlBusSendMailboxCommand must exist");

    // Direct C ABI Calls Verification
    uint32_t abiMaj = 0, abiMin = 0;
    NTSTATUS vSt = cxl::CxlHostGetVersion(&abiMaj, &abiMin);
    TEST_ASSERT(vSt == STATUS_SUCCESS && abiMaj == 3 && abiMin == 1, "CxlHostGetVersion C ABI call must succeed");

    uint32_t bridgeCount = 0;
    NTSTATUS brSt = cxl::CxlHostEnumerateBridges(&bridgeCount);
    TEST_ASSERT(brSt == STATUS_SUCCESS && bridgeCount >= 1, "CxlHostEnumerateBridges C ABI call must succeed");

    cxl::CxlDeviceInfo abiDev{};
    NTSTATUS dSt = cxl::CxlMemGetDeviceInfo(1, &abiDev);
    TEST_ASSERT(dSt == STATUS_SUCCESS && abiDev.totalMemoryBytes == 128ULL * 1024 * 1024 * 1024, "CxlMemGetDeviceInfo C ABI call must succeed");

    cxl::CxlSmartHealthInfo abiHealth{};
    NTSTATUS shSt = cxl::CxlMemGetSmartHealth(1, &abiHealth);
    TEST_ASSERT(shSt == STATUS_SUCCESS && abiHealth.healthStatus == 0, "CxlMemGetSmartHealth C ABI call must succeed");

    // Stage 16: SCM Service Control Manager Records & Version Database Registrations
    auto cxlHostSvc = scm::ServiceControlManager::get().getServiceRecord(L"cxlhost");
    TEST_ASSERT(cxlHostSvc != nullptr, "cxlhost service record must exist in SCM");
    TEST_ASSERT(cxlHostSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "cxlhost must be a kernel driver");
    TEST_ASSERT(cxlHostSvc->startType == scm::SERVICE_BOOT_START, "cxlhost must have boot start type");

    auto cxlMemSvc = scm::ServiceControlManager::get().getServiceRecord(L"cxlmem");
    TEST_ASSERT(cxlMemSvc != nullptr, "cxlmem service record must exist in SCM");
    TEST_ASSERT(cxlMemSvc->startType == scm::SERVICE_BOOT_START, "cxlmem must have boot start type");

    auto cxlBusSvc = scm::ServiceControlManager::get().getServiceRecord(L"cxlbus");
    TEST_ASSERT(cxlBusSvc != nullptr, "cxlbus service record must exist in SCM");
    TEST_ASSERT(cxlBusSvc->startType == scm::SERVICE_SYSTEM_START, "cxlbus must have system start type");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("cxlhost.sys") != nullptr, "cxlhost.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("cxlmem.sys") != nullptr, "cxlmem.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("cxlbus.sys") != nullptr, "cxlbus.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 162: Compute Express Link (CXL 2.0 / 3.1) & Heterogeneous Memory Fabric PASSED.\n";
}

void Test_IntelDSA_IAA_FastCopy_Subsystem() {
    std::cout << "[TEST] Starting Suite 172: Intel Data Streaming Accelerator (DSA) & In-Memory Analytics (IAA) Subsystem...\n";

    // Stage 1: Subsystem Initialization & Work Queue Enumeration
    auto& dsaSub = micant::dsa::TitanDsaSubsystem::Instance();
    bool initOk = dsaSub.initialize();
    TEST_ASSERT(initOk, "TitanDSA Subsystem must initialize successfully");
    TEST_ASSERT(dsaSub.isInitialized(), "TitanDSA Subsystem must report initialized state");

    auto wqs = dsaSub.getWorkQueues();
    TEST_ASSERT(wqs.size() == 8, "DSA/IAA must provide exactly 8 hardware work queues");
    TEST_ASSERT(wqs[0].mode == micant::dsa::WqMode::Dedicated, "WQ0 must be Dedicated Work Queue (DWQ)");
    TEST_ASSERT(wqs[0].portalAddress != 0, "WQ0 must possess valid MMIO portal address");

    // Stage 2: Hardware Capabilities & PCIe Identification
    const auto& caps = dsaSub.getCapabilities();
    TEST_ASSERT(caps.vendorId == 0x8086, "Vendor ID must match Intel (0x8086)");
    TEST_ASSERT(caps.dsaDeviceId == 0x0B25, "DSA Device ID must match Intel DSA (0x0B25)");
    TEST_ASSERT(caps.iaaDeviceId == 0x0CFE, "IAA Device ID must match Intel IAA (0x0CFE)");
    TEST_ASSERT(caps.numEngines == 4, "Subsystem must configure 4 physical DMA streaming engines");
    TEST_ASSERT(caps.supportsCrc32c, "Subsystem must support Castagnoli CRC-32C offload");
    TEST_ASSERT(caps.supportsDualCast, "Subsystem must support DualCast multi-destination replication");
    TEST_ASSERT(caps.maxBandwidthGbps > 80.0, "Subsystem peak memory bandwidth must exceed 80 GB/s");

    // Stage 3: Zero-Copy DMA Memory Transfer (MEMMOVE)
    size_t copyLen = 256 * 1024; // 256 KB
    std::vector<uint8_t> srcBuf(copyLen);
    for (size_t i = 0; i < copyLen; ++i) {
        srcBuf[i] = static_cast<uint8_t>((i * 17 + 5) & 0xFF);
    }
    std::vector<uint8_t> dstBuf(copyLen, 0x00);
    uint32_t moveLatencyNs = 0;
    bool moveOk = dsaSub.submitMemMove(dstBuf.data(), srcBuf.data(), copyLen, &moveLatencyNs);
    TEST_ASSERT(moveOk, "Hardware MEMMOVE DMA memory copy must succeed");
    TEST_ASSERT(dstBuf[0] == srcBuf[0], "First byte must match source");
    TEST_ASSERT(dstBuf[copyLen / 2] == srcBuf[copyLen / 2], "Middle byte must match source");
    TEST_ASSERT(dstBuf[copyLen - 1] == srcBuf[copyLen - 1], "Last byte must match source");

    // Stage 4: Sub-150ns Memory Copy Latency & Telemetry
    TEST_ASSERT(moveLatencyNs > 0 && moveLatencyNs < 200, "DMA dispatch latency must be under 200ns");
    const auto& telem1 = dsaSub.getTelemetry();
    TEST_ASSERT(telem1.totalMemMoveBytes >= copyLen, "Telemetry must track transferred memory bytes");
    TEST_ASSERT(telem1.totalMemMoveOps >= 1, "Telemetry must track MEMMOVE operation count");

    // Stage 5: Hardware Memory Pattern Fill (MEMFILL)
    size_t fillLen = 128 * 1024; // 128 KB
    std::vector<uint8_t> fillBuf(fillLen, 0x00);
    uint64_t pattern = 0xDEADBEEFCAFEBABFULL;
    uint32_t fillLatencyNs = 0;
    bool fillOk = dsaSub.submitMemFill(fillBuf.data(), pattern, fillLen, &fillLatencyNs);
    TEST_ASSERT(fillOk, "Hardware MEMFILL must succeed");
    uint64_t* checkPtr = reinterpret_cast<uint64_t*>(fillBuf.data());
    TEST_ASSERT(checkPtr[0] == pattern, "First 64-bit word must match pattern");
    TEST_ASSERT(checkPtr[100] == pattern, "100th word must match pattern");
    TEST_ASSERT(checkPtr[(fillLen / 8) - 1] == pattern, "Last word must match pattern");

    // Stage 6: High-Speed Memory Zeroing (MEMFILL with 0)
    bool zeroOk = dsaSub.submitMemFill(fillBuf.data(), 0, fillLen);
    TEST_ASSERT(zeroOk, "High-speed memory zeroing must succeed");
    TEST_ASSERT(checkPtr[0] == 0, "Zeroed memory must be 0");
    TEST_ASSERT(checkPtr[(fillLen / 8) - 1] == 0, "Last word must be 0");

    // Stage 7: Hardware Delta Comparison (COMPARE) with Identical Buffers
    std::vector<uint8_t> comp1(64 * 1024, 0x77);
    std::vector<uint8_t> comp2(64 * 1024, 0x77);
    bool matchOk = false;
    size_t mismatchOffset = 0;
    bool cmp1Ok = dsaSub.submitMemCompare(comp1.data(), comp2.data(), comp1.size(), &matchOk, &mismatchOffset);
    TEST_ASSERT(cmp1Ok, "Hardware memory comparison must execute successfully");
    TEST_ASSERT(matchOk, "Identical buffers must report match == true");
    TEST_ASSERT(mismatchOffset == comp1.size(), "Mismatch offset on match must equal length");

    // Stage 8: Hardware Delta Mismatch Detection & Offset Localization
    comp2[12345] = 0x88; // Inject single-byte mismatch
    matchOk = true;
    mismatchOffset = 0;
    bool cmp2Ok = dsaSub.submitMemCompare(comp1.data(), comp2.data(), comp1.size(), &matchOk, &mismatchOffset);
    TEST_ASSERT(cmp2Ok, "Hardware delta comparison with mismatch must succeed");
    TEST_ASSERT(!matchOk, "Mismatching buffers must report match == false");
    TEST_ASSERT(mismatchOffset == 12345, "Mismatch offset must pinpoint exact corrupted byte (12345)");

    // Stage 9: Hardware Castagnoli CRC-32C Checksum Calculation
    std::string crcPayload = "MicaNT_Storage_NVMe_FastPath_DirectStorage_CRC32C_Test_Payload_String";
    uint32_t crc1 = 0;
    uint32_t crcLatency = 0;
    bool crcOk = dsaSub.submitCrc32c(crcPayload.data(), crcPayload.size(), 0, &crc1, &crcLatency);
    TEST_ASSERT(crcOk, "Hardware Castagnoli CRC-32C must succeed");
    TEST_ASSERT(crc1 != 0, "Calculated CRC-32C value must be non-zero");

    // Stage 10: Simultaneous Memory Copy and CRC-32C Generation (COPY_CRC)
    std::vector<uint8_t> copyCrcDst(crcPayload.size(), 0);
    uint32_t crc2 = 0;
    bool copyCrcOk = dsaSub.submitCopyCrc(copyCrcDst.data(), crcPayload.data(), crcPayload.size(), 0, &crc2);
    TEST_ASSERT(copyCrcOk, "Hardware COPY_CRC single-pass operation must succeed");
    TEST_ASSERT(crc1 == crc2, "COPY_CRC checksum must perfectly match standalone CRC32C");
    TEST_ASSERT(std::memcmp(copyCrcDst.data(), crcPayload.data(), crcPayload.size()) == 0, "Destination data must match source");

    // Stage 11: Hardware DualCast Multi-Destination Replication
    size_t dualLen = 32 * 1024;
    std::vector<uint8_t> dualSrc(dualLen, 0x33);
    std::vector<uint8_t> dualDst1(dualLen, 0x00);
    std::vector<uint8_t> dualDst2(dualLen, 0x00);
    bool dualOk = dsaSub.submitDualCast(dualDst1.data(), dualDst2.data(), dualSrc.data(), dualLen);
    TEST_ASSERT(dualOk, "Hardware DualCast must execute successfully");
    TEST_ASSERT(dualDst1[0] == 0x33 && dualDst1[dualLen - 1] == 0x33, "Destination 1 must contain replicated data");
    TEST_ASSERT(dualDst2[0] == 0x33 && dualDst2[dualLen - 1] == 0x33, "Destination 2 must contain replicated data");

    // Stage 12: In-Memory Analytics (IAA): Columnar Predicate Scan
    size_t colSize = 2048;
    std::vector<uint32_t> column(colSize);
    for (size_t i = 0; i < colSize; ++i) {
        column[i] = static_cast<uint32_t>(i);
    }
    std::vector<uint8_t> bitmask((colSize + 7) / 8, 0);
    size_t matchingRows = 0;
    bool scanOk = dsaSub.submitIaaScan(column.data(), colSize, 500, 1000, bitmask.data(), &matchingRows);
    TEST_ASSERT(scanOk, "In-Memory Analytics (IAA) columnar scan must succeed");
    TEST_ASSERT(matchingRows == 501, "Scan predicate [500 <= val <= 1000] must match exactly 501 rows");
    TEST_ASSERT((bitmask[500 / 8] & (1 << (500 % 8))) != 0, "Bit 500 in result bitmask must be 1");
    TEST_ASSERT((bitmask[499 / 8] & (1 << (499 % 8))) == 0, "Bit 499 in result bitmask must be 0");

    // Stage 13: In-Memory Analytics (IAA): Bit-Packed Integer Extraction
    std::vector<uint8_t> packedCol = { 0xA5, 0xF3 };
    std::vector<uint32_t> extracted(4, 0);
    bool extractOk = dsaSub.submitIaaExtract(packedCol.data(), 4, 4, extracted.data());
    TEST_ASSERT(extractOk, "In-Memory Analytics (IAA) column extraction must succeed");
    TEST_ASSERT(extracted[0] == 0x5, "Extracted value 0 must be 0x5");
    TEST_ASSERT(extracted[1] == 0xA, "Extracted value 1 must be 0xA");
    TEST_ASSERT(extracted[2] == 0x3, "Extracted value 2 must be 0x3");
    TEST_ASSERT(extracted[3] == 0xF, "Extracted value 3 must be 0xF");

    // Stage 14: Telemetry Monotonic Counter Updates
    const auto& telemFinal = dsaSub.getTelemetry();
    TEST_ASSERT(telemFinal.totalDescriptorsSubmitted >= 10, "Total submitted descriptors must be >= 10");
    TEST_ASSERT(telemFinal.totalCompareOps >= 2, "Compare ops must be >= 2");
    TEST_ASSERT(telemFinal.totalIaaScanOps >= 1, "IAA scan ops must be >= 1");
    TEST_ASSERT(telemFinal.totalIaaExtractOps >= 1, "IAA extract ops must be >= 1");

    // Stage 15: C ABI Driver Exports
    uint32_t cMajor = 0, cMinor = 0, cBuild = 0;
    int32_t vStat = micant::dsa::DsaGetVersion(&cMajor, &cMinor, &cBuild);
    TEST_ASSERT(vStat == micant::dsa::STATUS_SUCCESS, "DsaGetVersion must succeed");
    TEST_ASSERT(cMajor == 10 && cBuild == 26100, "DSA version must match 10.0.26100");

    uint8_t cSrc[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t cDst[16] = {0};
    uint32_t cLat = 0;
    int32_t cCopyStat = micant::dsa::DsaSubmitMemCopy(cDst, cSrc, sizeof(cSrc), &cLat);
    TEST_ASSERT(cCopyStat == micant::dsa::STATUS_SUCCESS, "DsaSubmitMemCopy C ABI must succeed");
    TEST_ASSERT(cDst[0] == 1 && cDst[15] == 16, "C ABI copied data must match source");

    // Stage 16: SCM Boot Driver Registration & Version Database
    auto& scm = micant::scm::ServiceControlManager::get();
    auto dsaSvc = scm.getServiceRecord(L"intel_dsa");
    TEST_ASSERT(dsaSvc != nullptr, "intel_dsa.sys must be registered in SCM");
    TEST_ASSERT(dsaSvc->startType == micant::scm::SERVICE_BOOT_START, "intel_dsa must be Boot start");

    auto iaaSvc = scm.getServiceRecord(L"intel_iaa");
    TEST_ASSERT(iaaSvc != nullptr, "intel_iaa.sys must be registered in SCM");
    TEST_ASSERT(iaaSvc->startType == micant::scm::SERVICE_SYSTEM_START, "intel_iaa must be System start");

    const auto* modDsa = micant::version::VersionDatabase::Instance().GetModuleInfo("intel_dsa.sys");
    TEST_ASSERT(modDsa != nullptr, "intel_dsa.sys must be registered in VersionDatabase");
    TEST_ASSERT(modDsa->stringTable.at("ProductVersion") == "10.0.26100.1", "intel_dsa.sys version must match 10.0.26100.1");

    std::cout << "[TEST] Suite 172: Intel Data Streaming Accelerator (DSA) & In-Memory Analytics (IAA) Subsystem PASSED.\n";
}

void Test_WDDM32_GraphicsKernel_Subsystem() {
    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 156: Windows Display Driver Model (WDDM 3.2) & Graphics Kernel  \n";
    std::cout << "========================================================================\n";

    // Initialize WDDM Subsystem defensively
    wddm::InitializeWddmSubsystem();
    auto& wddmSub = wddm::TitanWddmSubsystem::Instance();
    TEST_ASSERT(wddmSub.isInitialized(), "TitanWddmSubsystem must be initialized");

    // Stage 1: PCIe Discrete GPU Discovery (Bus 01:00.0)
    auto primaryGpu = wddmSub.getPrimaryAdapter();
    TEST_ASSERT(primaryGpu != nullptr, "Primary WDDM graphics adapter must exist");
    TEST_ASSERT(primaryGpu->getPciVendorId() == 0x10DE, "Primary GPU vendor must match NVIDIA/Sovereign (0x10DE)");
    TEST_ASSERT(primaryGpu->getPciDeviceId() == 0x2684, "Primary GPU device ID must match RTX 4090 class (0x2684)");
    TEST_ASSERT(primaryGpu->getWddmVersion() == wddm::WddmVersion::WDDM_3_2, "Supported WDDM version must report WDDM 3.2");
    TEST_ASSERT(primaryGpu->getTotalVram() == 16ULL * 1024 * 1024 * 1024, "Primary GPU dedicated VRAM must report 16 GB");

    // Stage 2: Multi-Vendor Display Miniport Driver Bindings (NVIDIA, AMD, Intel, Sovereign)
    const auto& allAdapters = wddmSub.getAllAdapters();
    TEST_ASSERT(allAdapters.size() >= 3, "WDDM subsystem must discover at least 3 multi-vendor graphics adapters");
    TEST_ASSERT(allAdapters.count(0x1000) > 0, "Adapter 0x1000 (PrismX / NVIDIA) must exist");
    TEST_ASSERT(allAdapters.count(0x1001) > 0, "Adapter 0x1001 (AMD Radeon RX 7900 XTX) must exist");
    TEST_ASSERT(allAdapters.count(0x1002) > 0, "Adapter 0x1002 (Intel Arc A770) must exist");

    auto amdAdp = allAdapters.at(0x1001);
    TEST_ASSERT(amdAdp->getPciVendorId() == 0x1002, "AMD adapter vendor must be 0x1002");
    TEST_ASSERT(amdAdp->getMiniport() != nullptr, "AMD miniport driver must be bound");
    TEST_ASSERT(amdAdp->getMiniport()->getBinaryPath().find("amdkmdag.sys") != std::string::npos, "AMD miniport binary must be amdkmdag.sys");

    auto intelAdp = allAdapters.at(0x1002);
    TEST_ASSERT(intelAdp->getPciVendorId() == 0x8086, "Intel adapter vendor must be 0x8086");
    TEST_ASSERT(intelAdp->getMiniport()->getBinaryPath().find("igdkmdn64.sys") != std::string::npos, "Intel miniport binary must be igdkmdn64.sys");

    // Stage 3: Video Memory Manager (VidMm) Physical Memory Segments
    const auto& segments = primaryGpu->getSegments();
    TEST_ASSERT(segments.size() >= 2, "VidMm must report at least 2 physical memory segments (Aperture & Local VRAM)");
    TEST_ASSERT(segments[0].type == wddm::MemorySegmentType::ApertureSystem, "Segment 1 must be PCIe Aperture / GTT System Memory");
    TEST_ASSERT(segments[1].type == wddm::MemorySegmentType::LocalDedicated, "Segment 2 must be Dedicated On-Board VRAM");
    TEST_ASSERT(segments[1].totalBytes == 16ULL * 1024 * 1024 * 1024, "Local VRAM segment must report 16 GB capacity");

    // Stage 4: GPU Resource Allocation & 48-bit GPU Virtual Addressing (GPUVA)
    uint32_t hAlloc1 = primaryGpu->createAllocation(3840 * 2160 * 4, 2, wddm::PixelFormat::B8G8R8A8_UNORM, 3840, 2160, false);
    TEST_ASSERT(hAlloc1 != 0, "createAllocation must return non-zero allocation handle");
    auto allocRec1 = primaryGpu->getAllocation(hAlloc1);
    TEST_ASSERT(allocRec1 != nullptr, "Allocation record must be queryable in VidMm");
    TEST_ASSERT(allocRec1->isResident == true, "New allocation must be marked resident");
    TEST_ASSERT(allocRec1->gpuVirtualAddress >= 0x00007FF000000000ULL, "Allocation must have valid 48-bit GPUVA assigned");

    // Stage 5: Residency Management (Evict & MakeResident)
    TEST_ASSERT(primaryGpu->evict({ hAlloc1 }) == true, "VidMm evict must succeed");
    TEST_ASSERT(allocRec1->isResident == false, "Allocation must be in evicted state");
    TEST_ASSERT(primaryGpu->makeResident({ hAlloc1 }) == true, "VidMm makeResident must succeed");
    TEST_ASSERT(allocRec1->isResident == true, "Allocation must be restored to resident state");

    // Stage 6: Video Present Network (VidPN) Topology & Display Outputs
    const auto& sources = primaryGpu->getSources();
    const auto& targets = primaryGpu->getTargets();
    const auto& paths = primaryGpu->getPaths();
    TEST_ASSERT(sources.size() >= 2, "VidPN must support at least 2 Sources (Primary & Extended Desktop)");
    TEST_ASSERT(targets.size() >= 2, "VidPN must support at least 2 physical Targets (DisplayPort 2.1 & HDMI 2.1)");
    TEST_ASSERT(paths.size() >= 1, "VidPN must contain an active functional Path");
    TEST_ASSERT(paths[0].directFlipActive == true, "DirectFlip must be active on primary path");

    // Stage 7: Display Modes, Refresh Rates & HDR10 / scRGB Formats
    const auto& tgt0 = targets[0];
    TEST_ASSERT(tgt0.connectorType == wddm::VideoConnectorType::DisplayPort, "Target 0 must be DisplayPort connector");
    TEST_ASSERT(tgt0.supportsHdr == true, "Target 0 must report HDR support");
    TEST_ASSERT(tgt0.supportedModes.size() >= 4, "Target 0 must expose multiple display modes");
    TEST_ASSERT(tgt0.currentMode.width == 3840 && tgt0.currentMode.height == 2160, "Current mode must be 4K UHD (3840x2160)");
    TEST_ASSERT(tgt0.currentMode.getRefreshRateHz() == 120.0, "Current mode refresh rate must be 120 Hz");

    // Stage 8: Variable Refresh Rate (VRR: G-Sync / FreeSync)
    TEST_ASSERT(tgt0.supportsVrr == true, "Target 0 must report Variable Refresh Rate (VRR) support");
    TEST_ASSERT(tgt0.vrrMinHz == 48 && tgt0.vrrMaxHz == 240, "VRR range must be 48 Hz to 240 Hz");

    // Stage 9: Multi-Plane Overlay (MPO 3.0) Plane Configuration
    const auto& mpoPlanes = primaryGpu->getMpoPlanes();
    TEST_ASSERT(mpoPlanes.size() == 4, "MPO 3.0 must support 4 hardware composition planes");
    TEST_ASSERT(mpoPlanes[0].enabled == true, "Desktop plane (Plane 0) must be enabled");
    TEST_ASSERT(mpoPlanes[0].directFlipEnabled == true, "DirectFlip must be enabled on plane 0");

    // Stage 10: WDDM 3.2 Hardware Queues & Direct Engine Command Submission
    uint32_t q3d = primaryGpu->createHardwareQueue(1, wddm::GpuEngineType::ThreeD, wddm::HwQueuePriority::Normal);
    TEST_ASSERT(q3d != 0, "createHardwareQueue must return valid queue handle");

    uint32_t qCompute = primaryGpu->createHardwareQueue(1, wddm::GpuEngineType::Compute, wddm::HwQueuePriority::High);
    TEST_ASSERT(qCompute != 0, "createHardwareQueue for Async Compute must succeed");

    // Stage 11: 64-bit Monitored Fences & Hardware Synchronization
    uint32_t fence = primaryGpu->createMonitoredFence(0);
    TEST_ASSERT(fence != 0, "createMonitoredFence must return valid fence handle");
    TEST_ASSERT(primaryGpu->getFenceValue(fence) == 0, "Initial fence value must be 0");

    bool subCmd = primaryGpu->submitCommandToHwQueue(q3d, 0x00007FF000000000ULL, 2048, fence, 100);
    TEST_ASSERT(subCmd == true, "submitCommandToHwQueue must succeed");
    TEST_ASSERT(primaryGpu->getFenceValue(fence) == 100, "Monitored fence value must advance to 100 on GPU completion");
    TEST_ASSERT(primaryGpu->getTotalSubmissions() >= 1, "Total submissions counter must increment");

    // Stage 12: Frame Presentation & Vertical Blank (VBlank) Engine
    TEST_ASSERT(primaryGpu->present(0, hAlloc1) == true, "Frame presentation via DirectFlip must succeed");
    TEST_ASSERT(primaryGpu->getTotalPresents() >= 1, "Total presents counter must increment");
    primaryGpu->simulateVBlankInterrupt();
    TEST_ASSERT(primaryGpu->getTotalVBlanks() >= 1, "Total VBlank interrupts counter must increment");

    // Stage 13: Timeout Detection & Recovery (TDR) Watchdog & Engine Reset
    TEST_ASSERT(primaryGpu->getTdrState() == wddm::TdrState::Normal, "Initial TDR state must be Normal");
    bool tdrResult = primaryGpu->triggerTdrSimulation();
    TEST_ASSERT(tdrResult == true, "triggerTdrSimulation must execute recovery state machine");
    TEST_ASSERT(primaryGpu->getTdrState() == wddm::TdrState::Recovered, "TDR state must report Recovered without kernel crash");
    TEST_ASSERT(primaryGpu->getTdrRecoveryCount() >= 1, "TDR recovery counter must increment");

    // Stage 14: Dynamic Loader Exports (dxgkrnl.sys / displib.sys) & SCM Driver Records
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("dxgkrnl.sys", "DxgkInitialize") != nullptr, "dxgkrnl.sys DxgkInitialize export must exist");
    TEST_ASSERT(ldr.getExport("dxgkrnl.sys", "DxgkCreateDevice") != nullptr, "dxgkrnl.sys DxgkCreateDevice export must exist");
    TEST_ASSERT(ldr.getExport("dxgkrnl.sys", "DxgkCreateAllocation") != nullptr, "dxgkrnl.sys DxgkCreateAllocation export must exist");
    TEST_ASSERT(ldr.getExport("dxgkrnl.sys", "DxgkDestroyAllocation") != nullptr, "dxgkrnl.sys DxgkDestroyAllocation export must exist");
    TEST_ASSERT(ldr.getExport("dxgkrnl.sys", "DxgkCreateHwQueue") != nullptr, "dxgkrnl.sys DxgkCreateHwQueue export must exist");
    TEST_ASSERT(ldr.getExport("dxgkrnl.sys", "DxgkSubmitCommandHwQueue") != nullptr, "dxgkrnl.sys DxgkSubmitCommandHwQueue export must exist");
    TEST_ASSERT(ldr.getExport("dxgkrnl.sys", "DxgkPresentFrame") != nullptr, "dxgkrnl.sys DxgkPresentFrame export must exist");
    TEST_ASSERT(ldr.getExport("dxgkrnl.sys", "DxgkTriggerTdr") != nullptr, "dxgkrnl.sys DxgkTriggerTdr export must exist");
    TEST_ASSERT(ldr.getExport("displib.sys", "DxgkInitialize") != nullptr, "displib.sys DxgkInitialize export must exist");

    auto dxgSvc = scm::ServiceControlManager::get().getServiceRecord(L"dxgkrnl");
    TEST_ASSERT(dxgSvc != nullptr, "dxgkrnl service record must exist in SCM");
    TEST_ASSERT(dxgSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "dxgkrnl service type must be kernel driver");
    TEST_ASSERT(dxgSvc->startType == scm::SERVICE_BOOT_START, "dxgkrnl service start type must be boot start");

    auto dispSvc = scm::ServiceControlManager::get().getServiceRecord(L"displib");
    TEST_ASSERT(dispSvc != nullptr, "displib service record must exist in SCM");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("dxgkrnl.sys") != nullptr, "dxgkrnl.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("nvlddmkm.sys") != nullptr, "nvlddmkm.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("amdkmdag.sys") != nullptr, "amdkmdag.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("igdkmdn64.sys") != nullptr, "igdkmdn64.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("prismx_kmd.sys") != nullptr, "prismx_kmd.sys must be registered in Version Database");

    // Clean up test resources
    primaryGpu->destroyAllocation(hAlloc1);
    primaryGpu->destroyHardwareQueue(q3d);
    primaryGpu->destroyHardwareQueue(qCompute);

    std::cout << "[TEST] Suite 156: Windows Display Driver Model (WDDM 3.2) & Graphics Kernel PASSED.\n";
}

void Test_IntelHighDefinitionAudio_USBAudio_Subsystem() {
    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 155: Intel High Definition Audio (HDA 1.0a) & USB Audio 2.0     \n";
    std::cout << "========================================================================\n";

    // Initialize HDA Subsystem defensively
    hda::InitializeHdaSubsystem();
    auto& hdaSub = hda::TitanHdaSubsystem::Instance();
    TEST_ASSERT(hdaSub.isInitialized(), "TitanHdaSubsystem must be initialized");

    // Stage 1: PCI Device Discovery (00:05.0 Vendor 0x8086 Device 0x7AD0)
    auto pciAudio = pci::TitanPciSubsystem::Instance().findDeviceByVendorDevice(0x8086, 0x7AD0);
    TEST_ASSERT(pciAudio != nullptr, "PrismAudio HDA PCI device (00:05.0) must be discovered in PCI bus tree");
    TEST_ASSERT(pciAudio->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Multimedia), "PrismAudio device class must be Multimedia (0x04)");
    TEST_ASSERT(pciAudio->getSubClass() == 0x03, "PrismAudio subclass must be Audio Device (0x03)");
    TEST_ASSERT(hdaSub.getMmioBaseAddress() != 0, "HDA controller MMIO Base Address must be allocated non-zero");

    // Stage 2: Hardware Controller Reset & CRST State
    hdaSub.resetController();
    TEST_ASSERT(hda::HdaControllerReset() == win32::TRUE, "HdaControllerReset C ABI export must succeed");

    // Stage 3: Onboard Audio Codec Discovery (Address 0, Realtek ALC887 / Sovereign HDA)
    auto codec0 = hdaSub.getCodec(0);
    TEST_ASSERT(codec0 != nullptr, "Primary audio codec must be present at link address 0");
    TEST_ASSERT(codec0->getVendorId() == 0x10EC, "Codec vendor ID must be Realtek/Sovereign (0x10EC)");
    TEST_ASSERT(codec0->getDeviceId() == 0x0887, "Codec device ID must be ALC887 (0x0887)");
    TEST_ASSERT(codec0->getRevision() == 0x00010003, "Codec revision must be 0x00010003");

    uint16_t cVend = 0, cDev = 0;
    uint32_t cRev = 0;
    TEST_ASSERT(hda::HdaGetCodecInfo(0, &cVend, &cDev, &cRev) == win32::TRUE, "HdaGetCodecInfo export must succeed");
    TEST_ASSERT(cVend == 0x10EC && cDev == 0x0887, "Exported codec vendor/device must match ALC887");

    // Stage 4: Audio Function Group (Node 1) Enumeration
    uint32_t fgType = 0;
    hda::HdaSendVerb(0, 1, hda::HDA_VERB_GET_PARAM, hda::HDA_PARAM_FUNC_GROUP_TYPE, &fgType);
    TEST_ASSERT(fgType == 0x01, "Node 1 Function Group Type must be Audio (0x01)");

    uint32_t subNodeCount = 0;
    hda::HdaSendVerb(0, 1, hda::HDA_VERB_GET_PARAM, hda::HDA_PARAM_SUB_NODE_COUNT, &subNodeCount);
    uint16_t startNode = static_cast<uint16_t>(subNodeCount >> 16);
    uint16_t totalNodes = static_cast<uint16_t>(subNodeCount & 0xFFFF);
    TEST_ASSERT(startNode == 2 && totalNodes == 24, "AFG sub-nodes must start at 2 with 24 total widgets");

    // Stage 5: Audio Output Converter (DAC 0, Node 0x02) Capabilities & Formats
    uint32_t dacCaps = 0;
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_GET_PARAM, hda::HDA_PARAM_AUDIO_WIDGET_CAPS, &dacCaps);
    auto widgetType = static_cast<hda::HdaWidgetType>(dacCaps >> 20);
    TEST_ASSERT(widgetType == hda::HdaWidgetType::AudioOutput, "Node 0x02 widget type must be Audio Output (DAC)");

    uint32_t dacFmts = 0;
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_GET_PARAM, hda::HDA_PARAM_SUPPORTED_FORMATS, &dacFmts);
    TEST_ASSERT((dacFmts & 0x01) != 0, "DAC 0 must support 44.1 kHz PCM");
    TEST_ASSERT((dacFmts & 0x02) != 0, "DAC 0 must support 48.0 kHz PCM");

    // Stage 6: Codec Verb Execution (Stream/Channel, Amp Gain & Mute)
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_SET_STREAM_CHANNEL, (4 << 4) | 0, nullptr);
    uint32_t scResp = 0;
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_GET_STREAM_CHANNEL, 0, &scResp);
    TEST_ASSERT(((scResp >> 4) & 0x0F) == 4, "DAC 0 stream tag must be set to 4");
    TEST_ASSERT((scResp & 0x0F) == 0, "DAC 0 channel index must be 0");

    // Set Amp Gain to 0x7F (100% volume, unmuted)
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_SET_AMP_GAIN_MUTE, (1 << 13) | (1 << 12) | 0x7F, nullptr);
    uint32_t ampResp = 0;
    hda::HdaSendVerb(0, 0x02, hda::HDA_VERB_GET_AMP_GAIN_MUTE, 0, &ampResp);
    TEST_ASSERT((ampResp & 0x7F) == 0x7F, "Amp gain must report 0x7F (0 dB)");
    TEST_ASSERT((ampResp & (1 << 7)) == 0, "Amp must report unmuted");

    // Stage 7: Pin Complex & Jack Detection Sense (Nodes 0x14 Front HP & 0x15 Rear Line-Out)
    int32_t hpConnected = 0;
    TEST_ASSERT(hda::HdaGetJackStatus(0, 0x14, &hpConnected) == win32::TRUE, "HdaGetJackStatus Node 0x14 must succeed");
    TEST_ASSERT(hpConnected == win32::TRUE, "Headphone jack (Node 0x14) must report connected");

    int32_t micConnected = 0;
    hda::HdaGetJackStatus(0, 0x18, &micConnected);
    TEST_ASSERT(micConnected == win32::FALSE, "Mic jack (Node 0x18) must report disconnected initially");

    // Simulate Jack Insertion on Mic (Unsolicited Event)
    codec0->setJackConnected(0x18, true);
    hda::HdaGetJackStatus(0, 0x18, &micConnected);
    TEST_ASSERT(micConnected == win32::TRUE, "Mic jack (Node 0x18) must report connected after insertion event");

    // Stage 8: Hardware Stream Descriptor Allocation & Format Encoding
    auto streamOut4 = hdaSub.getStream(4);
    TEST_ASSERT(streamOut4 != nullptr, "Output Stream 4 must exist");
    TEST_ASSERT(streamOut4->isOutput() == true, "Stream 4 direction must be Output");

    uint16_t fmt48k = hda::HdaEncodeFormat(48000, 2, 16);
    TEST_ASSERT((fmt48k & (1 << 14)) == 0, "48kHz format must have bit 14 clear (48k base)");
    TEST_ASSERT((fmt48k & 0x0F) == 1, "2-channel format must have channel bits = 1");

    uint16_t fmt44k = hda::HdaEncodeFormat(44100, 2, 16);
    TEST_ASSERT((fmt44k & (1 << 14)) != 0, "44.1kHz format must have bit 14 set (44.1k base)");

    // Stage 9: Buffer Descriptor List (BDL) & Cyclic DMA Buffer Programming
    int32_t bdlRes = hda::HdaSetupStream(4, win32::TRUE, 48000, 2, 16, 0x78000000ULL, 8192);
    TEST_ASSERT(bdlRes == win32::TRUE, "HdaSetupStream for Stream 4 must succeed");
    TEST_ASSERT(streamOut4->getBufferLength() == 8192, "Stream 4 cyclic buffer length must be 8192 bytes");

    // Stage 10: Stream DMA Engine Lifecycle & Position Advancement
    TEST_ASSERT(hda::HdaStartStream(4) == win32::TRUE, "HdaStartStream must start DMA engine");
    TEST_ASSERT(streamOut4->isActive() == true, "Stream 4 must report active status");

    streamOut4->advanceDma(2048);
    uint32_t curPos = 0;
    TEST_ASSERT(hda::HdaGetStreamPosition(4, &curPos) == win32::TRUE, "HdaGetStreamPosition must succeed");
    TEST_ASSERT(curPos == 2048, "Stream 4 position must advance to 2048 bytes");

    streamOut4->advanceDma(8192); // Wrap around cyclic buffer
    hda::HdaGetStreamPosition(4, &curPos);
    TEST_ASSERT(curPos == 2048, "Cyclic buffer must wrap around modulo 8192");

    TEST_ASSERT(hda::HdaStopStream(4) == win32::TRUE, "HdaStopStream must stop stream");
    TEST_ASSERT(streamOut4->isActive() == false, "Stream 4 must report stopped status");

    // Stage 11: Realtime Hardware Tone DMA Synthesis & PrismAudio Integration
    int32_t toneRes = hda::HdaSynthesizeTone(4, 880.0f, 50, 0.7f); // 880 Hz A5 tone
    TEST_ASSERT(toneRes == win32::TRUE, "HdaSynthesizeTone must successfully write PCM samples and arm DMA");
    TEST_ASSERT(streamOut4->getVirtualBuffer().size() > 0, "Stream virtual buffer must contain synthesized PCM data");

    // USB Audio Class 2.0 (UAC2) Device Bridge
    auto& uac = hdaSub.getUsbAudio();
    TEST_ASSERT(uac.getSampleRate() == 48000, "UAC2 device must support 48000 Hz");
    TEST_ASSERT(uac.getBitsPerSample() == 24, "UAC2 device must support 24-bit studio resolution");
    uac.startStreaming();
    TEST_ASSERT(uac.isStreaming() == true, "UAC2 device must be actively streaming");
    uac.stopStreaming();

    // Stage 12: Driver Exports in hdaudio.sys & SCM Driver Registrations
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaControllerReset") != nullptr, "hdaudio.sys HdaControllerReset export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaSendVerb") != nullptr, "hdaudio.sys HdaSendVerb export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaSetupStream") != nullptr, "hdaudio.sys HdaSetupStream export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaStartStream") != nullptr, "hdaudio.sys HdaStartStream export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaStopStream") != nullptr, "hdaudio.sys HdaStopStream export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaGetStreamPosition") != nullptr, "hdaudio.sys HdaGetStreamPosition export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaGetCodecInfo") != nullptr, "hdaudio.sys HdaGetCodecInfo export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaGetJackStatus") != nullptr, "hdaudio.sys HdaGetJackStatus export must exist");
    TEST_ASSERT(ldr.getExport("hdaudio.sys", "HdaSynthesizeTone") != nullptr, "hdaudio.sys HdaSynthesizeTone export must exist");

    auto hdaSvc = scm::ServiceControlManager::get().getServiceRecord(L"hdaudio");
    TEST_ASSERT(hdaSvc != nullptr, "hdaudio service record must exist in SCM");
    TEST_ASSERT(hdaSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "hdaudio service type must be kernel driver");
    TEST_ASSERT(hdaSvc->startType == scm::SERVICE_BOOT_START, "hdaudio service start type must be boot start");

    auto uacSvc = scm::ServiceControlManager::get().getServiceRecord(L"usbaudio2");
    TEST_ASSERT(uacSvc != nullptr, "usbaudio2 service record must exist in SCM");

    auto hdaVer = version::VersionDatabase::Instance().GetModuleInfo("hdaudio.sys");
    TEST_ASSERT(hdaVer != nullptr, "hdaudio.sys must be registered in Version Database");
    TEST_ASSERT(hdaVer->stringTable.count("FileVersion") > 0, "hdaudio.sys FileVersion must exist");

    std::cout << "[TEST] Suite 155: Intel High Definition Audio & USB Audio PASSED.\n";
}

void Test_IntelThreadDirector_AMD_CPPC_HeterogeneousScheduling_Subsystem() {
    std::cout << "[TEST] Starting Suite 168: Intel Thread Director & AMD CPPC Heterogeneous Scheduling Subsystem...\n";

    // Stage 1: Subsystem Initialization & Version Query
    micant::hfi::InitializeHfiSubsystem();
    auto& dirSub = micant::hfi::TitanDirectorSubsystem::Instance();
    TEST_ASSERT(dirSub.isInitialized(), "HFI subsystem must be initialized");
    uint32_t ver = micant::hfi::HfiGetVersion();
    TEST_ASSERT(ver == 0x00010000, "HFI version must be 1.0 (0x00010000)");

    // Stage 2: Heterogeneous Processor Topology & Model Query
    char modelBuf[128]{};
    uint32_t coreCount = 0;
    NTSTATUS procStatus = micant::hfi::HfiGetProcessorInfo(modelBuf, sizeof(modelBuf), &coreCount);
    TEST_ASSERT(procStatus == STATUS_SUCCESS, "HfiGetProcessorInfo must return STATUS_SUCCESS");
    TEST_ASSERT(coreCount == 24, "Heterogeneous topology must report 24 logical cores");
    TEST_ASSERT(std::string(modelBuf).find("Hybrid") != std::string::npos, "CPU model string must identify Hybrid topology");

    // Stage 3: P-Core Topology & IPC Ratings
    micant::hfi::LogicalCoreDescriptor pCoreDesc{};
    TEST_ASSERT(micant::hfi::HfiGetCoreDescriptor(0, &pCoreDesc) == STATUS_SUCCESS, "Get Core #0 descriptor must succeed");
    TEST_ASSERT(pCoreDesc.coreType == micant::hfi::CoreType::P_Core, "Core #0 must be a Performance Core (P-Core)");
    TEST_ASSERT(pCoreDesc.maxBoostFreqMhz >= 5500, "P-Core max boost frequency must be >= 5.5 GHz");
    TEST_ASSERT(pCoreDesc.performanceRating >= 240, "P-Core performance rating must be >= 240");
    TEST_ASSERT(!pCoreDesc.isParked, "P-Core must initially be unparked");

    // Stage 4: E-Core Topology & Efficiency Ratings
    micant::hfi::LogicalCoreDescriptor eCoreDesc{};
    TEST_ASSERT(micant::hfi::HfiGetCoreDescriptor(10, &eCoreDesc) == STATUS_SUCCESS, "Get Core #10 descriptor must succeed");
    TEST_ASSERT(eCoreDesc.coreType == micant::hfi::CoreType::E_Core, "Core #10 must be an Efficient Core (E-Core)");
    TEST_ASSERT(eCoreDesc.efficiencyRating >= 200, "E-Core efficiency rating must be >= 200");
    TEST_ASSERT(eCoreDesc.maxBoostFreqMhz >= 4000, "E-Core max boost frequency must be >= 4.0 GHz");

    // Stage 5: Low-Power Island LP E-Core Verification
    micant::hfi::LogicalCoreDescriptor lpCoreDesc{};
    TEST_ASSERT(micant::hfi::HfiGetCoreDescriptor(22, &lpCoreDesc) == STATUS_SUCCESS, "Get Core #22 descriptor must succeed");
    TEST_ASSERT(lpCoreDesc.coreType == micant::hfi::CoreType::LP_E_Core, "Core #22 must be a Low-Power Island Core (LP E-Core)");
    TEST_ASSERT(lpCoreDesc.efficiencyRating == 255, "LP E-Core must have maximum efficiency rating 255");
    TEST_ASSERT(lpCoreDesc.clusterId == 99, "LP E-Core must be on dedicated SoC island cluster");

    // Stage 6: Class 1 (Vector / AVX-512) Thread Scheduling
    uint32_t targetCore1 = 0;
    uint32_t freq1 = 0;
    NTSTATUS schedStatus1 = micant::hfi::HfiScheduleThread(static_cast<uint32_t>(micant::hfi::ThreadClass::Class1_VectorAVX), &targetCore1, &freq1);
    TEST_ASSERT(schedStatus1 == STATUS_SUCCESS, "Scheduling Class 1 vector thread must succeed");
    TEST_ASSERT(targetCore1 < 8, "Vector intensive thread must be scheduled on a P-Core (Cores 0..7)");
    TEST_ASSERT(freq1 >= 4500, "P-Core operating frequency must be >= 4500 MHz for vector workloads");

    // Stage 7: Class 2 (Matrix / AI Inference) Thread Scheduling
    uint32_t targetCore2 = 0;
    uint32_t freq2 = 0;
    NTSTATUS schedStatus2 = micant::hfi::HfiScheduleThread(static_cast<uint32_t>(micant::hfi::ThreadClass::Class2_MatrixAI), &targetCore2, &freq2);
    TEST_ASSERT(schedStatus2 == STATUS_SUCCESS, "Scheduling Class 2 matrix thread must succeed");
    TEST_ASSERT(targetCore2 < 8, "Matrix/AI inference thread must be scheduled on a P-Core");

    // Stage 8: Class 3 (Low Latency / UI Presentation) Scheduling
    uint32_t targetCore3 = 0;
    uint32_t freq3 = 0;
    NTSTATUS schedStatus3 = micant::hfi::HfiScheduleThread(static_cast<uint32_t>(micant::hfi::ThreadClass::Class3_LatencyUI), &targetCore3, &freq3);
    TEST_ASSERT(schedStatus3 == STATUS_SUCCESS, "Scheduling Class 3 UI thread must succeed");
    TEST_ASSERT(targetCore3 < 8, "Latency-critical UI presentation thread must be scheduled on a P-Core");

    // Stage 9: Class 4 (Background I/O / Telemetry) Scheduling
    uint32_t targetCore4 = 0;
    uint32_t freq4 = 0;
    NTSTATUS schedStatus4 = micant::hfi::HfiScheduleThread(static_cast<uint32_t>(micant::hfi::ThreadClass::Class4_Background), &targetCore4, &freq4);
    TEST_ASSERT(schedStatus4 == STATUS_SUCCESS, "Scheduling Class 4 background thread must succeed");
    TEST_ASSERT(targetCore4 >= 8, "Background thread must be offloaded to an E-Core or LP E-Core (Cores 8..23)");

    // Stage 10: Class 0 (Standard Integer) Scheduling
    uint32_t targetCore0 = 0;
    NTSTATUS schedStatus0 = micant::hfi::HfiScheduleThread(static_cast<uint32_t>(micant::hfi::ThreadClass::Class0_Standard), &targetCore0, nullptr);
    TEST_ASSERT(schedStatus0 == STATUS_SUCCESS, "Scheduling Class 0 standard thread must succeed");
    TEST_ASSERT(targetCore0 >= 8 && targetCore0 < 22, "Standard integer thread should default to standard E-Cores");

    // Stage 11: Autonomous Core Parking
    micant::hfi::HfiTelemetry telemBefore{};
    micant::hfi::HfiGetTelemetry(&telemBefore);
    NTSTATUS parkStatus = micant::hfi::HfiSetCoreParking(7, 1); // Park P-Core #7
    TEST_ASSERT(parkStatus == STATUS_SUCCESS, "HfiSetCoreParking to park must succeed");
    micant::hfi::LogicalCoreDescriptor parkedDesc{};
    micant::hfi::HfiGetCoreDescriptor(7, &parkedDesc);
    TEST_ASSERT(parkedDesc.isParked == true, "Core #7 must be marked as parked");
    TEST_ASSERT(parkedDesc.powerState == micant::hfi::CorePowerState::Parked, "Core #7 power state must be Parked");
    micant::hfi::HfiTelemetry telemAfterPark{};
    micant::hfi::HfiGetTelemetry(&telemAfterPark);
    TEST_ASSERT(telemAfterPark.parkedCores == telemBefore.parkedCores + 1, "Telemetry parked core count must increment");

    // Stage 12: Core Unparking & Dynamic Re-enabling
    NTSTATUS unparkStatus = micant::hfi::HfiSetCoreParking(7, 0); // Unpark P-Core #7
    TEST_ASSERT(unparkStatus == STATUS_SUCCESS, "HfiSetCoreParking to unpark must succeed");
    micant::hfi::HfiGetCoreDescriptor(7, &parkedDesc);
    TEST_ASSERT(parkedDesc.isParked == false, "Core #7 must be marked as unparked");
    TEST_ASSERT(parkedDesc.powerState == micant::hfi::CorePowerState::C0_Active, "Core #7 power state must return to C0_Active");

    // Stage 13: CPPC Energy-Performance Preference Policy
    NTSTATUS cppcMaxPerf = micant::hfi::CppcSetEnergyPreference(0);
    TEST_ASSERT(cppcMaxPerf == STATUS_SUCCESS, "Setting CPPC EPP to MaxPerf (0) must succeed");
    TEST_ASSERT(dirSub.getEnergyPerformancePreference() == 0, "Global EPP must be 0");
    NTSTATUS cppcBalanced = micant::hfi::CppcSetEnergyPreference(128);
    TEST_ASSERT(cppcBalanced == STATUS_SUCCESS, "Setting CPPC EPP to Balanced (128) must succeed");
    TEST_ASSERT(dirSub.getEnergyPerformancePreference() == 128, "Global EPP must be 128");

    // Stage 14: Dynamic Loader C ABI Symbol Resolution
    auto& ldr = micant::ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("intel_hfi.sys", "HfiInitialize") != nullptr, "intel_hfi.sys!HfiInitialize must be exported");
    TEST_ASSERT(ldr.getExport("intel_hfi.sys", "HfiGetProcessorInfo") != nullptr, "intel_hfi.sys!HfiGetProcessorInfo must be exported");
    TEST_ASSERT(ldr.getExport("intel_hfi.sys", "HfiGetCoreDescriptor") != nullptr, "intel_hfi.sys!HfiGetCoreDescriptor must be exported");
    TEST_ASSERT(ldr.getExport("intel_hfi.sys", "HfiScheduleThread") != nullptr, "intel_hfi.sys!HfiScheduleThread must be exported");
    TEST_ASSERT(ldr.getExport("intel_hfi.sys", "HfiSetCoreParking") != nullptr, "intel_hfi.sys!HfiSetCoreParking must be exported");
    TEST_ASSERT(ldr.getExport("intel_hfi.sys", "HfiGetTelemetry") != nullptr, "intel_hfi.sys!HfiGetTelemetry must be exported");
    TEST_ASSERT(ldr.getExport("amd_cppc.sys", "CppcSetEnergyPreference") != nullptr, "amd_cppc.sys!CppcSetEnergyPreference must be exported");

    // Stage 15: Service Control Manager (SCM) Registration
    auto hfiSvc = micant::scm::ServiceControlManager::get().getServiceRecord(L"intel_hfi");
    TEST_ASSERT(hfiSvc != nullptr, "intel_hfi service record must exist in SCM");
    TEST_ASSERT(hfiSvc->serviceType == micant::scm::SERVICE_KERNEL_DRIVER, "intel_hfi must be registered as SERVICE_KERNEL_DRIVER");
    TEST_ASSERT(hfiSvc->startType == micant::scm::SERVICE_BOOT_START, "intel_hfi must be configured as SERVICE_BOOT_START");
    auto cppcSvc = micant::scm::ServiceControlManager::get().getServiceRecord(L"amd_cppc");
    TEST_ASSERT(cppcSvc != nullptr, "amd_cppc service record must exist in SCM");
    TEST_ASSERT(cppcSvc->startType == micant::scm::SERVICE_BOOT_START, "amd_cppc must be configured as SERVICE_BOOT_START");

    // Stage 16: Version Database Module Registration
    const auto* modHfi = micant::version::VersionDatabase::Instance().GetModuleInfo("intel_hfi.sys");
    TEST_ASSERT(modHfi != nullptr, "intel_hfi.sys must be registered in VersionDatabase");
    TEST_ASSERT(modHfi->stringTable.at("ProductVersion") == "10.0.26100.1", "intel_hfi.sys version must match 10.0.26100.1");
    const auto* modCppc = micant::version::VersionDatabase::Instance().GetModuleInfo("amd_cppc.sys");
    TEST_ASSERT(modCppc != nullptr, "amd_cppc.sys must be registered in VersionDatabase");
    TEST_ASSERT(modCppc->stringTable.at("ProductVersion") == "10.0.26100.1", "amd_cppc.sys version must match 10.0.26100.1");

    std::cout << "[TEST] Suite 168: Intel Thread Director & AMD CPPC Heterogeneous Scheduling Subsystem PASSED.\n";
}

void Test_HardwareIOMMU_VTd_AMDVi_DMA_Remapping_Subsystem() {
    std::cout << "\n--- [Suite 175] Hardware-Accelerated IOMMU (Intel VT-d / AMD-Vi / Arm SMMUv3) Subsystem ---\n";

    auto& iommuSub = micant::iommu::TitanIommuSubsystem::Instance();

    // Stage 1: Hardware Initialization & Capability Enablement
    bool initOk = iommuSub.initialize();
    TEST_ASSERT(initOk, "TitanIOMMU hardware initialization must succeed");
    TEST_ASSERT(iommuSub.isInitialized(), "TitanIOMMU must report initialized state");

    // Stage 2: Protection Domain Lifecycle (Creation & Parameter Validation)
    int32_t dom1Stat = iommuSub.createDomain(1, 48); // 48-bit address width
    TEST_ASSERT(dom1Stat == micant::iommu::STATUS_SUCCESS, "Domain 1 creation must succeed");
    int32_t dom2Stat = iommuSub.createDomain(2, 48);
    TEST_ASSERT(dom2Stat == micant::iommu::STATUS_SUCCESS, "Domain 2 creation must succeed");

    int32_t dupDomStat = iommuSub.createDomain(1, 48);
    TEST_ASSERT(dupDomStat == micant::iommu::STATUS_INVALID_PARAMETER, "Duplicate domain creation must return STATUS_INVALID_PARAMETER");

    const auto& doms = iommuSub.getDomains();
    TEST_ASSERT(doms.find(1) != doms.end(), "Domain 1 must exist in domain map");
    TEST_ASSERT(doms.find(2) != doms.end(), "Domain 2 must exist in domain map");
    TEST_ASSERT(doms.at(1).addressWidth == 48, "Domain 1 address width must be 48 bits");

    // Stage 3: Device Attachment to Protection Domains
    micant::iommu::IommuBdf gpuBdf(1, 0, 0); // Bus 1, Dev 0, Fn 0 (GPU)
    micant::iommu::IommuBdf nicBdf(2, 0, 0); // Bus 2, Dev 0, Fn 0 (100GbE NIC)
    int32_t attachGpu = iommuSub.attachDevice(gpuBdf, 1, false);
    TEST_ASSERT(attachGpu == micant::iommu::STATUS_SUCCESS, "Attaching GPU to Domain 1 must succeed");
    int32_t attachNic = iommuSub.attachDevice(nicBdf, 2, false);
    TEST_ASSERT(attachNic == micant::iommu::STATUS_SUCCESS, "Attaching NIC to Domain 2 must succeed");

    const auto& devMap = iommuSub.getDeviceAssignments();
    TEST_ASSERT(devMap.find(gpuBdf.toRaw()) != devMap.end(), "GPU BDF must be registered in device map");
    TEST_ASSERT(devMap.at(gpuBdf.toRaw()) == 1, "GPU must be mapped to Domain 1");
    TEST_ASSERT(devMap.at(nicBdf.toRaw()) == 2, "NIC must be mapped to Domain 2");

    // Stage 4: Multi-Page DMA Memory Mapping
    // Map 16KB (4 pages) for GPU IOVA 0x10000000 -> Host Phys 0x80000000 (RW)
    int32_t mapGpu = iommuSub.mapDmaRange(1, 0x10000000ULL, 0x80000000ULL, 0x4000, true, true);
    TEST_ASSERT(mapGpu == micant::iommu::STATUS_SUCCESS, "mapDmaRange for Domain 1 (GPU) must succeed");

    // Map 8KB (2 pages) for NIC IOVA 0x20000000 -> Host Phys 0x90000000 (Read-Only)
    int32_t mapNic = iommuSub.mapDmaRange(2, 0x20000000ULL, 0x90000000ULL, 0x2000, true, false);
    TEST_ASSERT(mapNic == micant::iommu::STATUS_SUCCESS, "mapDmaRange for Domain 2 (NIC Read-Only) must succeed");

    // Stage 5: DMAR Hardware DMA Address Translation (Cold Walk / IOTLB Miss)
    uint64_t physAddr1 = 0;
    uint32_t latency1 = 0;
    int32_t transStat1 = iommuSub.translateDma(gpuBdf, 0x10000080ULL, false, &physAddr1, &latency1);
    TEST_ASSERT(transStat1 == micant::iommu::STATUS_SUCCESS, "DMA translation 1 must succeed");
    TEST_ASSERT(physAddr1 == 0x80000080ULL, "Physical address must match 0x80000080");
    TEST_ASSERT(latency1 == 38, "Cold translation latency must be 38 ns (IOMMU hardware page walk)");

    // Stage 6: IOTLB Caching & Accelerated Hit Latency
    uint64_t physAddr2 = 0;
    uint32_t latency2 = 0;
    int32_t transStat2 = iommuSub.translateDma(gpuBdf, 0x10000100ULL, false, &physAddr2, &latency2);
    TEST_ASSERT(transStat2 == micant::iommu::STATUS_SUCCESS, "DMA translation 2 must succeed");
    TEST_ASSERT(physAddr2 == 0x80000100ULL, "Physical address must match 0x80000100");
    TEST_ASSERT(latency2 == 3, "Cached translation latency must be 3 ns (IOTLB hit)");

    // Stage 7: Second-Level Permission Violation Interception
    uint64_t violPhys = 0;
    int32_t violStat = iommuSub.translateDma(nicBdf, 0x20000040ULL, true, &violPhys, nullptr); // Attempt write on read-only domain
    TEST_ASSERT(violStat == micant::iommu::STATUS_ACCESS_VIOLATION, "DMA write to read-only mapping must return STATUS_ACCESS_VIOLATION");

    const auto& faults = iommuSub.getFaultLog();
    TEST_ASSERT(!faults.empty(), "Fault log must record permission violation");
    TEST_ASSERT(faults.back().faultReason == micant::iommu::FAULT_WRITE_PERMISSION_VIOLATION, "Fault reason must be FAULT_WRITE_PERMISSION_VIOLATION");

    // Stage 8: Unmapped Address Translation Fault Interception
    uint64_t unmappedPhys = 0;
    int32_t unmappedStat = iommuSub.translateDma(gpuBdf, 0xDEAD0000ULL, false, &unmappedPhys, nullptr);
    TEST_ASSERT(unmappedStat == micant::iommu::STATUS_ACCESS_VIOLATION, "Translating unmapped IOVA must yield STATUS_ACCESS_VIOLATION");
    TEST_ASSERT(iommuSub.getFaultLog().back().faultReason == micant::iommu::FAULT_UNMAPPED_ADDRESS, "Fault reason must be FAULT_UNMAPPED_ADDRESS");

    // Stage 9: Kernel DMA Protection & Drive-By Attack Blocking
    micant::iommu::IommuBdf rogueThb(5, 0, 0); // Rogue Thunderbolt 4 / USB4 device not attached
    uint64_t roguePhys = 0;
    int32_t rogueStat = iommuSub.translateDma(rogueThb, 0x80000000ULL, true, &roguePhys, nullptr);
    TEST_ASSERT(rogueStat == micant::iommu::STATUS_ACCESS_DENIED, "Unattached DMA device drive-by attack must be blocked with STATUS_ACCESS_DENIED");
    TEST_ASSERT(iommuSub.getFaultLog().back().faultReason == micant::iommu::FAULT_CONTEXT_ENTRY_NOT_PRESENT, "Fault reason must be FAULT_CONTEXT_ENTRY_NOT_PRESENT");
    TEST_ASSERT(iommuSub.getTelemetry().totalMaliciousDmaBlocked >= 1, "Malicious DMA attack counter must be incremented");

    // Stage 10: Device Pass-Through (Identity Mapping) Translation
    micant::iommu::IommuBdf ptDev(3, 0, 0);
    int32_t attachPt = iommuSub.attachDevice(ptDev, 1, true); // Pass-through = true
    TEST_ASSERT(attachPt == micant::iommu::STATUS_SUCCESS, "Attaching pass-through device must succeed");
    uint64_t ptPhys = 0;
    uint32_t ptLat = 0;
    int32_t ptStat = iommuSub.translateDma(ptDev, 0x40001234ULL, false, &ptPhys, &ptLat);
    TEST_ASSERT(ptStat == micant::iommu::STATUS_SUCCESS, "Pass-through DMA translation must succeed");
    TEST_ASSERT(ptPhys == 0x40001234ULL, "Pass-through physical address must match device address (1:1)");
    TEST_ASSERT(ptLat == 1, "Pass-through latency must be 1 ns");

    // Stage 11: Interrupt Remapping Table Entry (IRTE) Registration
    int32_t irte1Stat = iommuSub.registerIrte(10, 0x40, 0, gpuBdf, false, 0);
    TEST_ASSERT(irte1Stat == micant::iommu::STATUS_SUCCESS, "IRTE 10 registration for GPU must succeed");
    int32_t irte2Stat = iommuSub.registerIrte(11, 0x41, 1, nicBdf, false, 0);
    TEST_ASSERT(irte2Stat == micant::iommu::STATUS_SUCCESS, "IRTE 11 registration for NIC must succeed");

    // Stage 12: MSI/MSI-X Interrupt Remapping & Delivery
    uint8_t remapVec = 0;
    uint32_t remapApic = 0;
    int32_t remapStat = iommuSub.remapInterrupt(gpuBdf, 10, &remapVec, &remapApic);
    TEST_ASSERT(remapStat == micant::iommu::STATUS_SUCCESS, "Interrupt remapping for GPU must succeed");
    TEST_ASSERT(remapVec == 0x40, "Remapped interrupt vector must match 0x40");
    TEST_ASSERT(remapApic == 0, "Remapped APIC ID must match CPU 0");

    // Stage 13: Source ID (SID) Spoofing Interception
    uint8_t spoofVec = 0;
    uint32_t spoofApic = 0;
    int32_t spoofStat = iommuSub.remapInterrupt(rogueThb, 10, &spoofVec, &spoofApic); // Rogue device signals GPU's IRTE
    TEST_ASSERT(spoofStat == micant::iommu::STATUS_ACCESS_DENIED, "SID spoofing must be blocked with STATUS_ACCESS_DENIED");
    TEST_ASSERT(iommuSub.getFaultLog().back().faultReason == micant::iommu::FAULT_SID_VERIFICATION_FAILED, "Fault reason must be FAULT_SID_VERIFICATION_FAILED");

    // Stage 14: Posted Interrupts (PIR) Architecture
    int32_t postedStat = iommuSub.registerIrte(12, 0x50, 2, gpuBdf, true, 0xFED00000ULL);
    TEST_ASSERT(postedStat == micant::iommu::STATUS_SUCCESS, "Posted interrupt IRTE registration must succeed");
    uint8_t postVec = 0;
    uint32_t postApic = 0;
    int32_t postRemapStat = iommuSub.remapInterrupt(gpuBdf, 12, &postVec, &postApic);
    TEST_ASSERT(postRemapStat == micant::iommu::STATUS_SUCCESS, "Posted interrupt remapping must succeed");
    TEST_ASSERT(postVec == 0x50, "Posted interrupt vector must match 0x50");
    TEST_ASSERT(postApic == 2, "Posted interrupt APIC ID must match CPU 2");
    TEST_ASSERT(iommuSub.getTelemetry().totalPostedInterrupts >= 1, "Posted interrupts counter must increment");

    // Stage 15: IOTLB Invalidation & Domain Teardown
    int32_t unmapStat = iommuSub.unmapDmaRange(1, 0x10000000ULL, 0x4000);
    TEST_ASSERT(unmapStat == micant::iommu::STATUS_SUCCESS, "unmapDmaRange must succeed");
    uint64_t postUnmapPa = 0;
    int32_t postUnmapStat = iommuSub.translateDma(gpuBdf, 0x10000080ULL, false, &postUnmapPa, nullptr);
    TEST_ASSERT(postUnmapStat == micant::iommu::STATUS_ACCESS_VIOLATION, "Translating unmapped DMA range must fail");

    iommuSub.invalidateIotlbGlobal();
    TEST_ASSERT(iommuSub.getTelemetry().totalIotlbInvalidations >= 2, "totalIotlbInvalidations must be >= 2");

    int32_t detachStat = iommuSub.detachDevice(gpuBdf);
    TEST_ASSERT(detachStat == micant::iommu::STATUS_SUCCESS, "detachDevice must succeed");
    int32_t destroyStat = iommuSub.destroyDomain(1);
    TEST_ASSERT(destroyStat == micant::iommu::STATUS_SUCCESS, "destroyDomain must succeed");
    TEST_ASSERT(iommuSub.getDomains().find(1) == iommuSub.getDomains().end(), "Domain 1 must no longer exist");

    // Stage 16: SCM Boot Drivers, Version Database & C ABI Driver Exports
    auto& scm = micant::scm::ServiceControlManager::get();
    auto dmarSvc = scm.getServiceRecord(L"dmar");
    TEST_ASSERT(dmarSvc != nullptr, "dmar.sys must be registered in SCM");
    TEST_ASSERT(dmarSvc->startType == micant::scm::SERVICE_BOOT_START, "dmar.sys must be Boot start");

    auto iommuSvc = scm.getServiceRecord(L"iommu");
    TEST_ASSERT(iommuSvc != nullptr, "iommu.sys must be registered in SCM");
    TEST_ASSERT(iommuSvc->startType == micant::scm::SERVICE_BOOT_START, "iommu.sys must be Boot start");

    auto kdmaSvc = scm.getServiceRecord(L"kdmapt");
    TEST_ASSERT(kdmaSvc != nullptr, "kdmapt.sys must be registered in SCM");
    TEST_ASSERT(kdmaSvc->startType == micant::scm::SERVICE_SYSTEM_START, "kdmapt.sys must be System start");

    const auto* modDmar = micant::version::VersionDatabase::Instance().GetModuleInfo("dmar.sys");
    TEST_ASSERT(modDmar != nullptr, "dmar.sys must be registered in VersionDatabase");
    TEST_ASSERT(modDmar->stringTable.at("ProductVersion") == "10.0.26100.1", "dmar.sys version must match 10.0.26100.1");

    uint32_t cMajor = 0, cMinor = 0, cBuild = 0;
    int32_t vStat = micant::iommu::IommuGetVersion(&cMajor, &cMinor, &cBuild);
    TEST_ASSERT(vStat == micant::iommu::STATUS_SUCCESS, "IommuGetVersion must succeed");
    TEST_ASSERT(cMajor == 10 && cBuild == 26100, "IOMMU version must match 10.0.26100");

    int32_t cInvStat = micant::iommu::IommuInvalidateIotlbGlobal();
    TEST_ASSERT(cInvStat == micant::iommu::STATUS_SUCCESS, "IommuInvalidateIotlbGlobal C ABI must succeed");

    std::cout << "[TEST] Suite 175: Hardware-Accelerated IOMMU (Intel VT-d / AMD-Vi / Arm SMMUv3) Subsystem PASSED.\n";
}

void Test_NDIS688_HighSpeedNetworking_Subsystem() {
    std::cout << "[TEST] Starting Suite 157: NDIS 6.88 & High-Speed Network Adapter Subsystem (RazzleNet)...\n";

    // Stage 1: NDIS 6.88 Subsystem Initialization & Adapter Discovery
    ndis::InitializeNdisSubsystem();
    auto& ndisSub = ndis::TitanNdisSubsystem::Instance();
    TEST_ASSERT(ndisSub.isInitialized() == true, "NDIS subsystem must be initialized");
    TEST_ASSERT(ndisSub.getAdapterCount() >= 2, "At least 2 adapters must be registered (RazzleNet & Virtual)");

    // Stage 2: RazzleNet PCIe Miniport Discovery & Binding (BDF 00:04.0)
    auto primary = ndisSub.getPrimaryAdapter();
    TEST_ASSERT(primary != nullptr, "Primary network adapter must not be null");
    auto razzle = std::dynamic_pointer_cast<ndis::RazzleNetAdapter>(primary);
    TEST_ASSERT(razzle != nullptr, "Primary adapter must be RazzleNet 10GbE miniport");
    TEST_ASSERT(razzle->getPciAddress().bus == 0 && razzle->getPciAddress().device == 4 && razzle->getPciAddress().function == 0,
                "RazzleNet must bind to PCIe BDF 00:04.0");

    // Stage 3: MAC Address, Link State, and Link Speed Verification
    auto mac = razzle->getMacAddress();
    TEST_ASSERT(mac == ndis::MacAddress::razzleNetDefault(), "MAC address must match Sovereign RazzleNet default");
    TEST_ASSERT(mac.isBroadcast() == false, "Adapter MAC must not be broadcast");
    TEST_ASSERT(mac.isMulticast() == false, "Adapter MAC must not be multicast");
    TEST_ASSERT(razzle->getLinkState() == ndis::MediaConnectState::Connected, "Initial link state must be Connected");
    TEST_ASSERT(razzle->getSpeedBps() == 10'000'000'000ULL, "Default link speed must be 10 Gbps");

    // Stage 4: Dynamic Link Speed (40GbE / 100GbE) & MTU Tuning (Jumbo Frames)
    razzle->setLinkSpeed(40'000'000'000ULL);
    TEST_ASSERT(razzle->getSpeedBps() == 40'000'000'000ULL, "Link speed must update to 40 Gbps");
    razzle->setLinkSpeed(100'000'000'000ULL);
    TEST_ASSERT(razzle->getSpeedBps() == 100'000'000'000ULL, "Link speed must update to 100 Gbps");
    razzle->setLinkSpeed(10'000'000'000ULL); // restore 10G

    razzle->setMtu(static_cast<uint32_t>(ndis::JUMBO_MTU));
    TEST_ASSERT(razzle->getMtu() == ndis::JUMBO_MTU, "MTU must be configurable up to 9014 (Jumbo Frames)");
    razzle->setMtu(static_cast<uint32_t>(ndis::DEFAULT_MTU));
    TEST_ASSERT(razzle->getMtu() == ndis::DEFAULT_MTU, "MTU must restore to 1500 bytes");

    // Stage 5: NET_BUFFER & NET_BUFFER_LIST (NBL) Memory Pool Allocation & Recycling
    auto* pool = ndisSub.getNblPool();
    TEST_ASSERT(pool != nullptr, "NBL Pool must be allocated");
    size_t initActive = pool->getActiveCount();
    std::vector<uint8_t> dummyData = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    auto nbl1 = pool->allocate(dummyData);
    TEST_ASSERT(nbl1 != nullptr, "NBL allocation must succeed");
    TEST_ASSERT(nbl1->firstNetBuffer != nullptr, "NBL must contain firstNetBuffer");
    TEST_ASSERT(nbl1->firstNetBuffer->dataLength == dummyData.size(), "NB dataLength must match payload");
    TEST_ASSERT(pool->getActiveCount() == initActive + 1, "Pool active count must increment");

    pool->free(nbl1);
    TEST_ASSERT(pool->getActiveCount() == initActive, "Pool active count must decrement upon free");

    // Stage 6: Hardware Checksum Offload Engine (RFC 1071 1's Complement Sum)
    const uint8_t testIpHdr[] = {
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x64, // 192.168.1.100
        0xC0, 0xA8, 0x01, 0x01                          // 192.168.1.1
    };
    uint16_t csum = ndis::calculateIpChecksum(testIpHdr, sizeof(testIpHdr));
    TEST_ASSERT(csum != 0, "Calculated IP checksum must be non-zero");
    uint8_t verifiedHdr[sizeof(testIpHdr)];
    std::memcpy(verifiedHdr, testIpHdr, sizeof(testIpHdr));
    verifiedHdr[10] = static_cast<uint8_t>(csum >> 8);
    verifiedHdr[11] = static_cast<uint8_t>(csum & 0xFF);
    uint16_t verifyResult = ndis::calculateIpChecksum(verifiedHdr, sizeof(verifiedHdr));
    TEST_ASSERT(verifyResult == 0x0000 || verifyResult == 0xFFFF, "Checksum verification of complete header must evaluate to 0");

    // Stage 7: Large Send Offload v2 (LSOv2 / TSO) Segmentation
    auto& offloads = razzle->getOffloadCapabilities();
    TEST_ASSERT(offloads.lsoV2.enabled == true, "LSOv2 must be enabled by default");
    TEST_ASSERT(offloads.lsoV2.maxOffloadSize == 65536, "LSOv2 max offload size must be 64KB");

    std::vector<uint8_t> largePayload(4096, 0x55);
    auto largeFrame = ndis::buildEthernetFrame(
        ndis::MacAddress::broadcast(),
        razzle->getMacAddress(),
        ndis::ETHERTYPE_IPV4,
        largePayload
    );
    auto lsoStatus = razzle->sendPacket(largeFrame);
    TEST_ASSERT(lsoStatus == NtStatus::Success, "LSOv2 large packet transmission must succeed");
    auto statsAfterLso = razzle->getStatistics();
    TEST_ASSERT(statsAfterLso.lsoPackets >= 2, "LSO segmentation must produce at least 2 hardware segments");

    // Stage 8: Receive Side Scaling (RSS) 40-byte Toeplitz Hash & Indirection Table
    auto& rss = razzle->getRssParameters();
    TEST_ASSERT(rss.enabled == true, "RSS must be enabled by default");
    TEST_ASSERT(rss.numCpuQueues == 4, "Default RSS CPU queues must be 4");

    std::vector<uint8_t> sampleFlow = { 192, 168, 1, 100, 192, 168, 1, 1, 0x1F, 0x90, 0x00, 0x50 };
    uint32_t hashVal = ndis::computeToeplitzHash(sampleFlow, rss.secretKey);
    TEST_ASSERT(hashVal != 0, "Toeplitz hash must compute a non-zero 32-bit hash");
    uint8_t targetCpu = rss.getTargetCpu(hashVal);
    TEST_ASSERT(targetCpu < rss.numCpuQueues, "Target CPU must be within configured queue range");

    // Stage 9: High-Speed TX DMA Ring Descriptors & MMIO Doorbells
    auto& rings = razzle->getRingBuffer();
    uint32_t preTxCompleted = static_cast<uint32_t>(rings.txCompleted);

    std::vector<uint8_t> stdPayload(128, 0x77);
    auto stdFrame = ndis::buildEthernetFrame(
        ndis::MacAddress::broadcast(),
        razzle->getMacAddress(),
        ndis::ETHERTYPE_IPV4,
        stdPayload
    );
    auto txStatus = razzle->sendPacket(stdFrame);
    TEST_ASSERT(txStatus == NtStatus::Success, "Standard frame transmission must succeed");
    TEST_ASSERT(rings.txCompleted == preTxCompleted + 1, "TX completed counter must increment");
    TEST_ASSERT(razzle->readMmio32(ndis::RazzleNetAdapter::REG_TDH) == rings.txHead, "MMIO TDH must match ring txHead");
    TEST_ASSERT(razzle->readMmio32(ndis::RazzleNetAdapter::REG_TDT) == rings.txTail, "MMIO TDT must match ring txTail");

    // Stage 10: High-Speed RX DMA Ring Descriptors & Packet Ingestion
    bool rxInvoked = false;
    size_t rxBytesReceived = 0;
    razzle->registerReceiveHandler([&](std::span<const uint8_t> pkt) {
        rxInvoked = true;
        rxBytesReceived = pkt.size();
    });

    uint32_t preRxCompleted = static_cast<uint32_t>(rings.rxCompleted);
    razzle->receivePacket(stdFrame);
    TEST_ASSERT(rxInvoked == true, "Receive handler must be invoked on packet ingestion");
    TEST_ASSERT(rxBytesReceived == stdFrame.size(), "Received packet byte size must match transmitted size");
    TEST_ASSERT(rings.rxCompleted == preRxCompleted + 1, "RX completed counter must increment");

    // Stage 11: Single Root I/O Virtualization (SR-IOV) VF Provisioning
    auto& sriov = razzle->getSriovManager();
    TEST_ASSERT(sriov.enableSriov(8) == true, "Enabling 8 Virtual Functions (VFs) must succeed");
    TEST_ASSERT(sriov.getActiveVfCount() == 8, "Active VF count must be 8");
    ndis::MacAddress vfMac(0x52, 0x5A, 0x00, 0x04, 0x01, 0x03);
    TEST_ASSERT(sriov.configureVf(3, vfMac, 100, 2500, true) == true, "Configuring VF #3 (VLAN 100, 2.5G) must succeed");
    const auto* vf3 = sriov.getVf(3);
    TEST_ASSERT(vf3 != nullptr && vf3->allocated == true, "VF #3 must be allocated");
    TEST_ASSERT(vf3->vfMac == vfMac, "VF #3 MAC must match configured MAC");
    TEST_ASSERT(vf3->vlanId == 100, "VF #3 VLAN ID must be 100");
    TEST_ASSERT(vf3->maxRateMbps == 2500, "VF #3 rate limit must be 2500 Mbps");

    // Stage 12: Dual Adapter Virtual Bus & Inter-Adapter Communication
    auto vnetAdp = std::dynamic_pointer_cast<ndis::VirtualNetworkAdapter>(ndisSub.getAdapter(L"vnet0"));
    TEST_ASSERT(vnetAdp != nullptr, "Virtual network adapter (vnet0) must exist");
    auto vnetStats = vnetAdp->getStatistics();
    TEST_ASSERT(vnetAdp->getMtu() == ndis::DEFAULT_MTU, "vnet0 MTU must be 1500");

    // Stage 13: Dynamic Loader C ABI Exports (ndis.sys & razzlenet.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisMRegisterMiniportDriver") != nullptr, "ndis.sys NdisMRegisterMiniportDriver export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisAllocateNetBufferListPool") != nullptr, "ndis.sys NdisAllocateNetBufferListPool export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisAllocateNetBufferList") != nullptr, "ndis.sys NdisAllocateNetBufferList export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisFreeNetBufferList") != nullptr, "ndis.sys NdisFreeNetBufferList export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisMIndicateReceiveNetBufferLists") != nullptr, "ndis.sys NdisMIndicateReceiveNetBufferLists export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisMSendNetBufferListsComplete") != nullptr, "ndis.sys NdisMSendNetBufferListsComplete export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisQueryAdapterInformation") != nullptr, "ndis.sys NdisQueryAdapterInformation export must exist");

    TEST_ASSERT(ldr.getExport("razzlenet.sys", "RazzleNetInitializeMiniport") != nullptr, "razzlenet.sys RazzleNetInitializeMiniport export must exist");
    TEST_ASSERT(ldr.getExport("razzlenet.sys", "RazzleNetTransmitPacket") != nullptr, "razzlenet.sys RazzleNetTransmitPacket export must exist");

    // Stage 14: SCM Service Records & Version Database Verification
    auto ndisSvc = scm::ServiceControlManager::get().getServiceRecord(L"ndis");
    TEST_ASSERT(ndisSvc != nullptr, "ndis service record must exist in SCM");
    TEST_ASSERT(ndisSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "ndis must be a kernel driver");
    TEST_ASSERT(ndisSvc->startType == scm::SERVICE_BOOT_START, "ndis must have boot start type");

    auto razzleSvc = scm::ServiceControlManager::get().getServiceRecord(L"razzlenet");
    TEST_ASSERT(razzleSvc != nullptr, "razzlenet service record must exist in SCM");
    TEST_ASSERT(razzleSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "razzlenet must be a kernel driver");
    TEST_ASSERT(razzleSvc->startType == scm::SERVICE_SYSTEM_START, "razzlenet must have system start type");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("ndis.sys") != nullptr, "ndis.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("razzlenet.sys") != nullptr, "razzlenet.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 157: NDIS 6.88 & High-Speed Network Adapter Subsystem (RazzleNet) PASSED.\n";
}

void Test_NeuralProcessingUnit_MCDM_DirectML_Subsystem() {
    std::cout << "[TEST] Starting Suite 161: Neural Processing Unit (NPU) & MCDM Subsystem...\n";

    // Initialize Subsystem & Register Components
    pci::InitializePciSubsystem();
    npu::InitializeNpuSubsystem();
    auto& npuSub = npu::TitanNpuSubsystem::Instance();
    TEST_ASSERT(npuSub.isInitialized() == true, "TitanNPU subsystem must be initialized");

    // Stage 1: PCIe Miniport Binding (Bus 00:08.0)
    auto pciDev = pci::TitanPciSubsystem::Instance().findDevice(pci::PciAddress(0, 8, 0));
    TEST_ASSERT(pciDev != nullptr, "TitanNPU PCIe device must be registered at 00:08.0");
    TEST_ASSERT(pciDev->getVendorId() == 0x8086, "NPU Vendor ID must be 0x8086 (Intel / Titan)");
    TEST_ASSERT(pciDev->getDeviceId() == 0x7D1D, "NPU Device ID must be 0x7D1D (Core Ultra Arrow Lake NPU 4000)");
    TEST_ASSERT(pciDev->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Accelerator), "Base class must be Accelerator (0x12)");
    TEST_ASSERT(pciDev->getSubClass() == 0x00, "Subclass must be 0x00");

    // Stage 2: Base Address Registers (BAR0 MMIO & BAR2 SRAM Window)
    const auto& bar0 = pciDev->getBar(0);
    TEST_ASSERT(bar0.type == pci::PciBarType::Memory64, "BAR0 must be 64-bit MMIO");
    TEST_ASSERT(bar0.size == 16 * 1024 * 1024, "BAR0 MMIO size must be 16 MB");
    const auto& bar2 = pciDev->getBar(2);
    TEST_ASSERT(bar2.type == pci::PciBarType::Memory64, "BAR2 must be 64-bit MMIO");
    TEST_ASSERT(bar2.prefetchable == true, "BAR2 SRAM cache window must be prefetchable");
    TEST_ASSERT(bar2.size == 128 * 1024 * 1024, "BAR2 SRAM size must be 128 MB");

    // Stage 3: Subsystem Initialization & Copilot+ PC Capability Discovery (>= 40 TOPS)
    const auto& caps = npuSub.getCapabilities();
    TEST_ASSERT(caps.architecture == npu::NpuArchitecture::Titan_Sovereign, "Architecture must match Titan Sovereign");
    TEST_ASSERT(caps.numTiles == 4, "NPU must contain 4 compute tiles");
    TEST_ASSERT(caps.totalSramBytes == 16 * 1024 * 1024, "Total on-chip SRAM must be 16 MB");
    TEST_ASSERT(caps.peakInt8Tops >= 40.0f, "Peak INT8 TOPS must meet or exceed Microsoft 40 TOPS Copilot+ requirement");
    TEST_ASSERT(caps.peakInt8Tops == 48.0f, "Peak INT8 rating must be 48.0 TOPS");
    TEST_ASSERT(caps.peakFp16Tflops == 24.0f, "Peak FP16 rating must be 24.0 TFLOPS");
    TEST_ASSERT(caps.peakFp8Tops == 48.0f, "Peak FP8 rating must be 48.0 TOPS");
    TEST_ASSERT(caps.copilotPlusCompliant == true, "NPU must be certified Copilot+ compliant");

    // Stage 4: Multi-Tile Array Inspection (4 Neural Compute Tiles @ 1600 MHz)
    auto tiles = npuSub.getTiles();
    TEST_ASSERT(tiles.size() == 4, "Tile array size must be 4");
    for (size_t i = 0; i < tiles.size(); ++i) {
        TEST_ASSERT(tiles[i].tileId == static_cast<uint8_t>(i), "Tile ID must match index");
        TEST_ASSERT(tiles[i].frequencyMhz == 1600, "Tile frequency must be 1600 MHz");
        TEST_ASSERT(tiles[i].sramBytes == 4 * 1024 * 1024, "Tile SRAM must be 4 MB");
        TEST_ASSERT(tiles[i].macUnits == 4096, "Tile MAC units must be 4,096 INT8 MACs");
        TEST_ASSERT(tiles[i].isActive == true, "Tile must default to active in D0 state");
    }

    // Stage 5: Precision & Data Types Matrix Verification
    TEST_ASSERT(caps.supportedPrecisions & static_cast<uint32_t>(npu::NpuPrecision::INT4), "INT4 quantization must be supported");
    TEST_ASSERT(caps.supportedPrecisions & static_cast<uint32_t>(npu::NpuPrecision::INT8), "INT8 quantization must be supported");
    TEST_ASSERT(caps.supportedPrecisions & static_cast<uint32_t>(npu::NpuPrecision::FP8_E4M3), "FP8 E4M3 must be supported");
    TEST_ASSERT(caps.supportedPrecisions & static_cast<uint32_t>(npu::NpuPrecision::FP8_E5M2), "FP8 E5M2 must be supported");
    TEST_ASSERT(caps.supportedPrecisions & static_cast<uint32_t>(npu::NpuPrecision::FP16), "FP16 half-precision must be supported");
    TEST_ASSERT(caps.supportedPrecisions & static_cast<uint32_t>(npu::NpuPrecision::BF16), "BF16 bfloat16 must be supported");
    TEST_ASSERT(caps.supportedPrecisions & static_cast<uint32_t>(npu::NpuPrecision::FP32), "FP32 single-precision must be supported");

    // Stage 6: MCDM Virtual Memory Allocation & DVA Mapping (LocalSram & HostVisible)
    uint64_t sramAlloc = npuSub.allocateMemory(8 * 1024 * 1024, npu::McdmMemoryType::LocalSram, "Phi3_Weights_Cache");
    TEST_ASSERT(sramAlloc > 0, "SRAM allocation handle must be non-zero");
    const auto* allocDesc = npuSub.getAllocation(sramAlloc);
    TEST_ASSERT(allocDesc != nullptr, "Allocation lookup must succeed");
    TEST_ASSERT(allocDesc->sizeBytes == 8 * 1024 * 1024, "Allocation size must be 8 MB");
    TEST_ASSERT(allocDesc->deviceVirtualAddress >= 0x80000000ULL, "DVA must be in NPU virtual address range");
    TEST_ASSERT(allocDesc->memoryType == npu::McdmMemoryType::LocalSram, "Memory type must be LocalSram");

    uint64_t hostAlloc = npuSub.allocateMemory(16 * 1024 * 1024, npu::McdmMemoryType::HostVisible, "Host_Activation_Ring");
    TEST_ASSERT(hostAlloc > 0, "Host memory allocation handle must be non-zero");

    auto allocList = npuSub.listAllocations();
    TEST_ASSERT(allocList.size() >= 2, "Allocations list must contain both buffers");

    // Stage 7: MCDM Command Queue Creation (High Priority, MatrixMultiply Engine)
    auto q = npuSub.createCommandQueue(npu::McdmPriority::High, npu::McdmEngineType::MatrixMultiply);
    TEST_ASSERT(q != nullptr, "Command queue creation must succeed");
    TEST_ASSERT(q->getPriority() == npu::McdmPriority::High, "Command queue priority must be High");
    TEST_ASSERT(q->getEngine() == npu::McdmEngineType::MatrixMultiply, "Engine must be MatrixMultiply");

    // Stage 8: MCDM Command Buffer Submission & 64-bit Monotonic Fence Synchronization
    npu::McdmCommandPacket pkt{};
    pkt.opCode = npu::NpuOperator::MatMul;
    pkt.precision = npu::NpuPrecision::INT8;
    pkt.m = 256; pkt.n = 1024; pkt.k = 1024;
    pkt.inputDva = allocDesc->deviceVirtualAddress;
    pkt.weightsDva = allocDesc->deviceVirtualAddress;
    pkt.outputDva = allocDesc->deviceVirtualAddress;

    uint64_t fenceVal = q->submit({pkt});
    TEST_ASSERT(fenceVal == 1, "Initial submitted fence value must be 1");
    TEST_ASSERT(q->waitForFence(fenceVal, 1000) == true, "Fence wait must succeed for completed work");
    TEST_ASSERT(q->getCompletedFence() == fenceVal, "Completed fence must equal submitted fence");
    TEST_ASSERT(q->getProcessedCount() == 1, "Processed commands counter must increment to 1");

    // Free memory
    bool freeOk = npuSub.freeMemory(sramAlloc);
    TEST_ASSERT(freeOk == true, "Freeing memory allocation must succeed");
    TEST_ASSERT(npuSub.getAllocation(sramAlloc) == nullptr, "Freed allocation must be removed from table");
    npuSub.freeMemory(hostAlloc);

    // Stage 9: Hardware Power State Transitions (D0_Active -> D0_LowPower -> D3_Hot)
    TEST_ASSERT(npuSub.getPowerState() == npu::NpuPowerState::D0_Active, "Power state must be D0_Active");
    npuSub.setPowerState(npu::NpuPowerState::D0_LowPower);
    TEST_ASSERT(npuSub.getPowerState() == npu::NpuPowerState::D0_LowPower, "Power state must be D0_LowPower");
    auto lpTiles = npuSub.getTiles();
    TEST_ASSERT(lpTiles[0].frequencyMhz == 800 && lpTiles[1].frequencyMhz == 0, "Low power must clock gate inactive tiles");

    npuSub.setPowerState(npu::NpuPowerState::D3_Hot);
    TEST_ASSERT(npuSub.getPowerState() == npu::NpuPowerState::D3_Hot, "Power state must transition to D3_Hot");

    // Stage 10: Pre-compiled Model Catalog Inspection
    auto models = npuSub.getRegisteredModels();
    TEST_ASSERT(models.size() >= 5, "Model catalog must contain at least 5 registered AI workloads");
    const auto* phi3 = npuSub.findModel("phi-3-mini-4k-instruct");
    TEST_ASSERT(phi3 != nullptr, "Phi-3 Mini SLM must be present in catalog");
    TEST_ASSERT(phi3->precision == npu::NpuPrecision::INT4, "Phi-3 must use INT4 quantization");
    TEST_ASSERT(phi3->parameterCountBillions > 3.5f, "Phi-3 parameter count must be ~3.8B");

    const auto* llama3 = npuSub.findModel("llama-3-8b-instruct-int4");
    TEST_ASSERT(llama3 != nullptr, "LLaMA-3 8B must be present in catalog");

    const auto* directSr = npuSub.findModel("directsr-superres-4x");
    TEST_ASSERT(directSr != nullptr, "DirectSR super-resolution model must be present in catalog");

    // Stage 11: Hardware-Accelerated Small Language Model Inference (Phi-3 Auto-Wake & Execution)
    auto inferRes = npuSub.executeModel("phi-3-mini-4k-instruct", 128, 64);
    TEST_ASSERT(inferRes.success == true, "Phi-3 Mini inference execution must succeed");
    TEST_ASSERT(npuSub.getPowerState() == npu::NpuPowerState::D0_Active, "Inference submission must auto-wake NPU to D0_Active");
    TEST_ASSERT(inferRes.generatedTokens == 64, "Generated tokens must match request (64 tokens)");
    TEST_ASSERT(inferRes.tokensPerSecond > 30.0f, "Generation speed must exceed 30 tokens/sec on dedicated NPU");
    TEST_ASSERT(inferRes.effectiveTops > 0.0f, "Effective TOPS must be reported positive");
    TEST_ASSERT(inferRes.outputText.find("DirectML") != std::string::npos, "Output must confirm DirectML NPU acceleration");

    // Stage 12: DirectSR Real-Time Convolutional Super-Resolution Inference
    auto srRes = npuSub.executeModel("directsr-superres-4x", 1, 1);
    TEST_ASSERT(srRes.success == true, "DirectSR execution must succeed");
    TEST_ASSERT(srRes.tokensPerSecond >= 200.0f, "DirectSR throughput must achieve >= 200 FPS");

    // Stage 13: Synthetic Hardware Stress Benchmark & Microsoft Copilot+ Compliance Certification
    auto bench = npuSub.runBenchmark();
    TEST_ASSERT(bench.int8TopsAchieved >= 45.0f, "Benchmark must measure at least 45 INT8 TOPS");
    TEST_ASSERT(bench.fp16TflopsAchieved >= 20.0f, "Benchmark must measure at least 20 FP16 TFLOPS");
    TEST_ASSERT(bench.passesCopilotPlusStandard == true, "Benchmark must certify Copilot+ PC compliance (>= 40 TOPS)");
    TEST_ASSERT(bench.summary.find("PASSED") != std::string::npos, "Benchmark summary must state PASSED");

    // Stage 14: Telemetry Accounting
    auto telem = npuSub.getTelemetry();
    TEST_ASSERT(telem.totalInferences >= 3, "Total inferences counter must increment");
    TEST_ASSERT(telem.totalTokensGenerated >= 64, "Total tokens generated must increment");
    TEST_ASSERT(telem.totalMacOperations > 0, "MAC operations accounting must be non-zero");
    TEST_ASSERT(telem.currentPowerWatts > 0.0f, "Telemetry power draw must be non-zero");
    TEST_ASSERT(telem.temperatureCelsius > 20.0f && telem.temperatureCelsius < 100.0f, "Die temperature must be in valid operational range");

    // Stage 15: Dynamic Loader C ABI Driver Exports (mcdm.sys, npu.sys, titannpu.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("mcdm.sys", "McdmDeviceCreate") != nullptr, "mcdm.sys McdmDeviceCreate must exist");
    TEST_ASSERT(ldr.getExport("mcdm.sys", "McdmDeviceDestroy") != nullptr, "mcdm.sys McdmDeviceDestroy must exist");
    TEST_ASSERT(ldr.getExport("mcdm.sys", "McdmCreateCommandQueue") != nullptr, "mcdm.sys McdmCreateCommandQueue must exist");
    TEST_ASSERT(ldr.getExport("mcdm.sys", "McdmSubmitCommandBuffer") != nullptr, "mcdm.sys McdmSubmitCommandBuffer must exist");
    TEST_ASSERT(ldr.getExport("mcdm.sys", "McdmSignalFence") != nullptr, "mcdm.sys McdmSignalFence must exist");
    TEST_ASSERT(ldr.getExport("mcdm.sys", "McdmWaitForFence") != nullptr, "mcdm.sys McdmWaitForFence must exist");
    TEST_ASSERT(ldr.getExport("mcdm.sys", "McdmAllocateVirtualMemory") != nullptr, "mcdm.sys McdmAllocateVirtualMemory must exist");
    TEST_ASSERT(ldr.getExport("mcdm.sys", "McdmFreeVirtualMemory") != nullptr, "mcdm.sys McdmFreeVirtualMemory must exist");

    TEST_ASSERT(ldr.getExport("npu.sys", "NpuGetCapabilities") != nullptr, "npu.sys NpuGetCapabilities must exist");
    TEST_ASSERT(ldr.getExport("npu.sys", "NpuExecuteModel") != nullptr, "npu.sys NpuExecuteModel must exist");
    TEST_ASSERT(ldr.getExport("npu.sys", "NpuSetPowerState") != nullptr, "npu.sys NpuSetPowerState must exist");
    TEST_ASSERT(ldr.getExport("npu.sys", "NpuGetTelemetry") != nullptr, "npu.sys NpuGetTelemetry must exist");

    TEST_ASSERT(ldr.getExport("titannpu.sys", "TitanNpuHardwareReset") != nullptr, "titannpu.sys TitanNpuHardwareReset must exist");

    // Direct C ABI Calls Verification
    npu::HANDLE hDevice = nullptr;
    pci::PciAddress npuAddr(0, 8, 0);
    NTSTATUS devSt = npu::McdmDeviceCreate(npuAddr.toBdf(), &hDevice);
    TEST_ASSERT(devSt == STATUS_SUCCESS && hDevice != nullptr, "McdmDeviceCreate C ABI call must succeed");

    npu::HANDLE hQueue = nullptr;
    NTSTATUS qSt = npu::McdmCreateCommandQueue(hDevice, 1, 1, &hQueue);
    TEST_ASSERT(qSt == STATUS_SUCCESS && hQueue != nullptr, "McdmCreateCommandQueue C ABI call must succeed");

    uint64_t cAbiFence = 0;
    NTSTATUS subSt = npu::McdmSubmitCommandBuffer(hQueue, nullptr, 0, &cAbiFence);
    TEST_ASSERT(subSt == STATUS_SUCCESS && cAbiFence > 0, "McdmSubmitCommandBuffer C ABI call must succeed");

    NTSTATUS waitSt = npu::McdmWaitForFence(hQueue, cAbiFence, 100);
    TEST_ASSERT(waitSt == STATUS_SUCCESS, "McdmWaitForFence C ABI call must succeed");

    npu::NpuCapabilities abiCaps{};
    NTSTATUS capsSt = npu::NpuGetCapabilities(&abiCaps);
    TEST_ASSERT(capsSt == STATUS_SUCCESS && abiCaps.peakInt8Tops >= 40.0f, "NpuGetCapabilities C ABI call must succeed");

    npu::McdmDeviceDestroy(hDevice);

    // Stage 16: SCM Service Control Manager Records & Version Database Registrations
    auto mcdmSvc = scm::ServiceControlManager::get().getServiceRecord(L"mcdm");
    TEST_ASSERT(mcdmSvc != nullptr, "mcdm service record must exist in SCM");
    TEST_ASSERT(mcdmSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "mcdm must be a kernel driver");
    TEST_ASSERT(mcdmSvc->startType == scm::SERVICE_BOOT_START, "mcdm must have boot start type");

    auto npuSvc = scm::ServiceControlManager::get().getServiceRecord(L"npu");
    TEST_ASSERT(npuSvc != nullptr, "npu service record must exist in SCM");
    TEST_ASSERT(npuSvc->startType == scm::SERVICE_BOOT_START, "npu must have boot start type");

    auto titanNpuSvc = scm::ServiceControlManager::get().getServiceRecord(L"titannpu");
    TEST_ASSERT(titanNpuSvc != nullptr, "titannpu service record must exist in SCM");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("mcdm.sys") != nullptr, "mcdm.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("npu.sys") != nullptr, "npu.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("titannpu.sys") != nullptr, "titannpu.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 161: Neural Processing Unit (NPU) & MCDM Subsystem PASSED.\n";
}

void Test_NVMExpress_UniversalFlashStorage_Subsystem() {
    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 153: NVM Express (NVMe 1.0-2.0) & Universal Flash Storage       \n";
    std::cout << "========================================================================\n";

    // Initialize Subsystem
    nvme::InitializeNvmeSubsystem();
    auto& flashSub = nvme::TitanFlashSubsystem::Instance();
    auto nvmeCtrl = flashSub.getNvme();
    TEST_ASSERT(nvmeCtrl != nullptr, "NVMe controller must be instantiated in TitanFlash subsystem");

    // Stage 1: Multi-Generation Specification Versioning
    TEST_ASSERT(nvmeCtrl->getVersion() == nvme::NvmeVersion::Version_2_0, "Default NVMe version must be 2.0");
    TEST_ASSERT(nvme::NvmeVersionToString(nvmeCtrl->getVersion()) == "NVMe 2.0d", "Version string must report NVMe 2.0d");
    TEST_ASSERT(nvme::NvmeVersionToString(nvme::NvmeVersion::Version_1_4) == "NVMe 1.4b", "Backward version mapping must support NVMe 1.4b");
    TEST_ASSERT(nvme::NvmeVersionToString(nvme::NvmeVersion::Version_1_3) == "NVMe 1.3d", "Backward version mapping must support NVMe 1.3d");
    TEST_ASSERT(nvme::NvmeVersionToString(nvme::NvmeVersion::Version_1_0) == "NVMe 1.0e", "Backward version mapping must support legacy NVMe 1.0e");

    uint32_t vsReg = nvmeCtrl->readReg32(nvme::NVME_REG_VS);
    TEST_ASSERT(vsReg == static_cast<uint32_t>(nvme::NvmeVersion::Version_2_0), "VS register must match Version 2.0");

    uint32_t capLow = nvmeCtrl->readReg32(nvme::NVME_REG_CAP);
    TEST_ASSERT((capLow & 0xFFFF) == 0x03FF, "CAP.MQES must support 1024 queue entries (1023 0-based)");

    // Stage 2: Controller Reset & Enable Sequence
    win32::BOOL bReset = nvme::NvmeControllerReset();
    TEST_ASSERT(bReset == win32::TRUE, "NvmeControllerReset must succeed");
    TEST_ASSERT(nvmeCtrl->isReady(), "Controller must be in READY state after reset and enable");
    uint32_t csts = nvmeCtrl->readReg32(nvme::NVME_REG_CSTS);
    TEST_ASSERT((csts & nvme::NVME_CSTS_RDY) != 0, "CSTS.RDY bit must be set");

    // Stage 3: Admin Queue Ring Buffers & Phase Toggling
    nvme::NvmeSqe sqePing{};
    sqePing.opcode = nvme::NVME_ADMIN_GET_FEATURES;
    sqePing.commandId = 0x1001;
    nvme::NvmeCqe cqePing{};
    win32::BOOL bPing = nvme::NvmeSubmitAdminCommand(&sqePing, &cqePing, nullptr, 0);
    TEST_ASSERT(bPing == win32::TRUE, "Admin Get Features command must execute");
    TEST_ASSERT(cqePing.commandId == 0x1001, "CQE command ID must echo SQE command ID");
    TEST_ASSERT(cqePing.getPhase() == true, "CQE phase tag must be true");
    TEST_ASSERT(cqePing.getStatusCode() == nvme::NVME_SC_SUCCESS, "CQE status must be SUCCESS");

    // Stage 4: Admin Identify Controller
    nvme::NvmeIdentifyController idCtrl{};
    nvme::NvmeSqe sqeIdCtrl{};
    sqeIdCtrl.opcode = nvme::NVME_ADMIN_IDENTIFY;
    sqeIdCtrl.commandId = 0x1002;
    sqeIdCtrl.cdw10 = nvme::NVME_IDENTIFY_CNS_CTRL;
    nvme::NvmeCqe cqeIdCtrl{};
    win32::BOOL bIdCtrl = nvme::NvmeSubmitAdminCommand(&sqeIdCtrl, &cqeIdCtrl, &idCtrl, sizeof(idCtrl));
    TEST_ASSERT(bIdCtrl == win32::TRUE, "Identify Controller command must succeed");
    TEST_ASSERT(idCtrl.vid == 0x144D, "Controller Vendor ID must match 0x144D");
    TEST_ASSERT(std::string(idCtrl.mn).find("TitanNVMe") != std::string::npos, "Controller Model Number must contain TitanNVMe");
    TEST_ASSERT(idCtrl.ver == static_cast<uint32_t>(nvme::NvmeVersion::Version_2_0), "Controller version must report 2.0");
    TEST_ASSERT(idCtrl.nn >= 2, "Controller must advertise at least 2 active namespaces");

    // Stage 5: Multi-Namespace Architecture (512B vs 4096B 4Kn sectors)
    auto ns1 = nvmeCtrl->getNamespace(1);
    TEST_ASSERT(ns1 != nullptr, "Namespace 1 must exist");
    TEST_ASSERT(ns1->getBlockSize() == 512, "Namespace 1 block size must be 512 bytes");
    TEST_ASSERT(ns1->getTotalBlocks() > 1000000ULL, "Namespace 1 capacity must exceed 1M blocks");

    auto ns2 = nvmeCtrl->getNamespace(2);
    TEST_ASSERT(ns2 != nullptr, "Namespace 2 must exist");
    TEST_ASSERT(ns2->getBlockSize() == 4096, "Namespace 2 block size must be 4096 bytes (4Kn Advanced Format)");

    nvme::NvmeIdentifyNamespace idNs{};
    nvme::NvmeSqe sqeIdNs{};
    sqeIdNs.opcode = nvme::NVME_ADMIN_IDENTIFY;
    sqeIdNs.commandId = 0x1003;
    sqeIdNs.nsid = 1;
    sqeIdNs.cdw10 = nvme::NVME_IDENTIFY_CNS_NS;
    nvme::NvmeCqe cqeIdNs{};
    win32::BOOL bIdNs = nvme::NvmeSubmitAdminCommand(&sqeIdNs, &cqeIdNs, &idNs, sizeof(idNs));
    TEST_ASSERT(bIdNs == win32::TRUE, "Identify Namespace 1 must succeed");
    TEST_ASSERT(idNs.nsze == ns1->getTotalBlocks(), "Identify NSZE must equal namespace block count");
    TEST_ASSERT(idNs.lbaf[0].lbaDataSizeShift == 9, "Format 0 shift must be 9 (512 bytes)");
    TEST_ASSERT(idNs.lbaf[1].lbaDataSizeShift == 12, "Format 1 shift must be 12 (4096 bytes)");

    // Stage 6: Multi-Block NVM Read & Write Operations
    std::vector<uint8_t> payload(1024, 0x5A);
    nvme::NvmeSqe sqeWrite{};
    sqeWrite.opcode = nvme::NVME_NVM_WRITE;
    sqeWrite.commandId = 0x2001;
    sqeWrite.nsid = 1;
    sqeWrite.cdw10 = 500; // SLBA = 500
    sqeWrite.cdw12 = 1;   // NLB = 2 blocks (0-based)
    nvme::NvmeCqe cqeWrite{};
    win32::BOOL bWrite = nvme::NvmeSubmitIoCommand(&sqeWrite, &cqeWrite, payload.data(), 1024);
    TEST_ASSERT(bWrite == win32::TRUE, "NVMe Multi-Block Write must succeed");

    std::vector<uint8_t> readback(1024, 0x00);
    nvme::NvmeSqe sqeRead{};
    sqeRead.opcode = nvme::NVME_NVM_READ;
    sqeRead.commandId = 0x2002;
    sqeRead.nsid = 1;
    sqeRead.cdw10 = 500;
    sqeRead.cdw12 = 1;
    nvme::NvmeCqe cqeRead{};
    win32::BOOL bRead = nvme::NvmeSubmitIoCommand(&sqeRead, &cqeRead, readback.data(), 1024);
    TEST_ASSERT(bRead == win32::TRUE, "NVMe Multi-Block Read must succeed");
    TEST_ASSERT(std::memcmp(payload.data(), readback.data(), 1024) == 0, "Payload data written and read back must match byte-for-byte");

    // Stage 7: Volatile Cache Flush & Write Zeroes Operations
    nvme::NvmeSqe sqeFlush{};
    sqeFlush.opcode = nvme::NVME_NVM_FLUSH;
    sqeFlush.commandId = 0x2003;
    sqeFlush.nsid = 1;
    nvme::NvmeCqe cqeFlush{};
    win32::BOOL bFlush = nvme::NvmeSubmitIoCommand(&sqeFlush, &cqeFlush, nullptr, 0);
    TEST_ASSERT(bFlush == win32::TRUE, "NVMe Flush command must succeed");

    nvme::NvmeSqe sqeZero{};
    sqeZero.opcode = nvme::NVME_NVM_WRITE_ZEROES;
    sqeZero.commandId = 0x2004;
    sqeZero.nsid = 1;
    sqeZero.cdw10 = 500;
    sqeZero.cdw12 = 0; // 1 block
    nvme::NvmeCqe cqeZero{};
    win32::BOOL bZero = nvme::NvmeSubmitIoCommand(&sqeZero, &cqeZero, nullptr, 0);
    TEST_ASSERT(bZero == win32::TRUE, "NVMe Write Zeroes command must succeed");

    std::vector<uint8_t> zeroCheck(512, 0xFF);
    ns1->readBlocks(500, 1, zeroCheck.data());
    bool allZero = true;
    for (uint8_t b : zeroCheck) { if (b != 0) { allZero = false; break; } }
    TEST_ASSERT(allZero, "LBA 500 must contain all zeroes after Write Zeroes command");

    // Stage 8: Dataset Management (TRIM / Deallocate)
    uint8_t dsmData[16]{};
    *reinterpret_cast<uint32_t*>(dsmData + 4) = 5; // 5 blocks
    *reinterpret_cast<uint64_t*>(dsmData + 8) = 500; // SLBA 500
    nvme::NvmeSqe sqeDsm{};
    sqeDsm.opcode = nvme::NVME_NVM_DATASET_MGMT;
    sqeDsm.commandId = 0x2005;
    sqeDsm.nsid = 1;
    sqeDsm.cdw10 = 0; // 1 range (0-based)
    sqeDsm.cdw11 = 0x04; // Attribute: Deallocate
    nvme::NvmeCqe cqeDsm{};
    win32::BOOL bDsm = nvme::NvmeSubmitIoCommand(&sqeDsm, &cqeDsm, dsmData, sizeof(dsmData));
    TEST_ASSERT(bDsm == win32::TRUE, "NVMe Dataset Management (TRIM) must succeed");
    TEST_ASSERT(ns1->isTrimmed(500), "LBA 500 must be marked trimmed");
    TEST_ASSERT(ns1->isTrimmed(504), "LBA 504 must be marked trimmed");

    // Stage 9: S.M.A.R.T. / Health Information Telemetry Log
    nvme::NvmeSmartLog smart{};
    win32::BOOL bSmart = nvme::NvmeGetSmartLog(&smart);
    TEST_ASSERT(bSmart == win32::TRUE, "NvmeGetSmartLog must succeed");
    TEST_ASSERT(smart.compositeTemp > 273, "Temperature must be reported in Kelvin (> 273 K)");
    TEST_ASSERT(smart.availableSpare == 100, "Available spare must report 100% on healthy flash");
    TEST_ASSERT(smart.percentageUsed == 1, "Percentage used wear level must report 1%");
    TEST_ASSERT(smart.hostReadCommands[0] > 0, "Host read command telemetry counter must be greater than zero");
    TEST_ASSERT(smart.hostWriteCommands[0] > 0, "Host write command telemetry counter must be greater than zero");

    // Stage 10: Universal Flash Storage (UFS 3.1 & 4.0) Subsystem
    auto ufs = flashSub.getUfs();
    TEST_ASSERT(ufs != nullptr, "UFS host controller must exist");
    TEST_ASSERT(ufs->getVersion() == 0x00040000, "UFS version must report 4.0 (JESD220F)");
    TEST_ASSERT(ufs->isEnabled(), "UFS host controller must be enabled");
    TEST_ASSERT(ufs->getLunCount() == 2, "UFS must expose 2 LUNs (Boot LUN 0 and Data LUN 1)");
    auto lun0 = ufs->getLun(0);
    TEST_ASSERT(lun0 != nullptr, "UFS LUN 0 must exist");
    TEST_ASSERT(lun0->getBlockSize() == 4096, "UFS LUN 0 block size must be 4096 bytes");

    // Stage 11: eMMC 5.1 & AHCI 1.3.1 SATA SSD with NCQ
    auto emmc = flashSub.getEmmc();
    TEST_ASSERT(emmc != nullptr, "eMMC host controller must exist");
    TEST_ASSERT(emmc->getSpecVersion() == 0x0501, "eMMC specification version must be 5.1");
    auto emmcDev = emmc->getUserPartition();
    TEST_ASSERT(emmcDev != nullptr, "eMMC user partition must be accessible");

    auto ahci = flashSub.getAhci();
    TEST_ASSERT(ahci != nullptr, "AHCI SATA controller must exist");
    TEST_ASSERT(ahci->getVersion() == 0x00010301, "AHCI version must be 1.3.1");
    ahci->submitNcqCommand(7);
    TEST_ASSERT((ahci->getActiveTags() & (1U << 7)) != 0, "NCQ Tag 7 must be marked active");
    ahci->completeNcqCommand(7);
    TEST_ASSERT((ahci->getActiveTags() & (1U << 7)) == 0, "NCQ Tag 7 must be cleared after completion");

    // Stage 12: StorPort Miniport Driver Parity & SCM Registration
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("stornvme.sys", "NvmeControllerReset") != nullptr, "stornvme.sys NvmeControllerReset export must exist");
    TEST_ASSERT(ldr.getExport("stornvme.sys", "NvmeSubmitAdminCommand") != nullptr, "stornvme.sys NvmeSubmitAdminCommand export must exist");
    TEST_ASSERT(ldr.getExport("stornvme.sys", "NvmeSubmitIoCommand") != nullptr, "stornvme.sys NvmeSubmitIoCommand export must exist");
    TEST_ASSERT(ldr.getExport("stornvme.sys", "NvmeGetSmartLog") != nullptr, "stornvme.sys NvmeGetSmartLog export must exist");

    auto nvmeSvc = scm::ServiceControlManager::get().getServiceRecord(L"stornvme");
    TEST_ASSERT(nvmeSvc != nullptr, "stornvme service record must exist in SCM");
    TEST_ASSERT(nvmeSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "stornvme service type must be kernel driver");
    TEST_ASSERT(nvmeSvc->startType == scm::SERVICE_BOOT_START, "stornvme start type must be boot start");

    auto ahciSvc = scm::ServiceControlManager::get().getServiceRecord(L"storahci");
    TEST_ASSERT(ahciSvc != nullptr, "storahci service record must exist in SCM");

    auto ufsSvc = scm::ServiceControlManager::get().getServiceRecord(L"storufs");
    TEST_ASSERT(ufsSvc != nullptr, "storufs service record must exist in SCM");

    auto nvmeVer = version::VersionDatabase::Instance().GetModuleInfo("stornvme.sys");
    TEST_ASSERT(nvmeVer != nullptr, "stornvme.sys must be registered in Version Database");
    TEST_ASSERT(nvmeVer->stringTable.count("FileVersion") > 0, "stornvme.sys FileVersion must exist");

    // Verify PCIe device 02:00.0 integration
    auto pciDev = pci::TitanPciSubsystem::Instance().findDevice(pci::PciAddress(2, 0, 0));
    TEST_ASSERT(pciDev != nullptr, "PCIe device 02:00.0 (TitanNVMe) must exist on PCIe bus");
    TEST_ASSERT(pciDev->getVendorId() == 0x144D, "PCIe device 02:00.0 vendor must match Samsung/Titan NVMe");

    std::cout << "[TEST] Suite 153: NVM Express (NVMe 1.0-2.0) & Universal Flash Storage PASSED.\n";
}

void Test_PCIExpress_PCIe_Bus_Subsystem() {
    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 152: PCI Express (PCIe 5.0) Bus, Root Complex & AER Subsystem    \n";
    std::cout << "========================================================================\n";

    // Initialize Subsystem
    pci::InitializePciSubsystem();
    auto& pciSub = pci::TitanPciSubsystem::Instance();

    // Stage 1: PCI Configuration Space Header & Address Decoding
    pci::PciAddress addrGpu(1, 0, 0);
    TEST_ASSERT(addrGpu.bus == 1 && addrGpu.device == 0 && addrGpu.function == 0, "PciAddress BDF components must match");
    TEST_ASSERT(addrGpu.toBdf() == 0x0100, "BDF packing must equal 0x0100");
    TEST_ASSERT(pci::PciAddress::fromBdf(0x0100) == addrGpu, "BDF unpacking must recover original address");
    TEST_ASSERT(addrGpu.toString() == "01:00.0", "PciAddress toString formatting must match");

    auto gpu = pciSub.findDevice(addrGpu);
    TEST_ASSERT(gpu != nullptr, "PrismX GPU device 01:00.0 must be registered in PCI subsystem");
    TEST_ASSERT(gpu->getVendorId() == 0x10DE, "GPU Vendor ID must be NVIDIA/Sovereign 0x10DE");
    TEST_ASSERT(gpu->getDeviceId() == 0x2684, "GPU Device ID must be 0x2684");
    TEST_ASSERT(gpu->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Display), "GPU Base Class must be Display (0x03)");
    TEST_ASSERT(gpu->getHeaderType() == pci::PCI_HEADER_TYPE_NORMAL, "GPU Header Type must be Type 0 Normal Endpoint");

    // Stage 2: Base Address Register (BAR) Dynamic Sizing & Probing
    // BAR0: 16MB 32-bit Memory
    const auto& bar0 = gpu->getBar(0);
    TEST_ASSERT(bar0.type == pci::PciBarType::Memory32, "GPU BAR0 must be Memory32");
    TEST_ASSERT(bar0.size == 16 * 1024 * 1024, "GPU BAR0 size must be 16MB");
    TEST_ASSERT(!bar0.prefetchable, "GPU BAR0 control MMIO must not be prefetchable");

    // Simulate OS sizing probe on BAR0: write 0xFFFFFFFF, read back inverted size mask
    uint32_t origBar0 = gpu->readBar(0);
    gpu->writeBar(0, 0xFFFFFFFF);
    uint32_t maskBar0 = gpu->readBar(0);
    TEST_ASSERT((maskBar0 & 0xFF000000) == 0xFF000000, "BAR0 size probe mask must reflect 16MB boundary");
    gpu->writeBar(0, origBar0);

    // BAR1: 16GB 64-bit Memory Prefetchable
    const auto& bar1 = gpu->getBar(1);
    TEST_ASSERT(bar1.type == pci::PciBarType::Memory64, "GPU BAR1 must be Memory64");
    TEST_ASSERT(bar1.size == 16ULL * 1024 * 1024 * 1024, "GPU BAR1 size must be 16GB VRAM");
    TEST_ASSERT(bar1.prefetchable, "GPU BAR1 VRAM must be prefetchable");

    // BAR3: I/O Space (128 bytes)
    const auto& bar3 = gpu->getBar(3);
    TEST_ASSERT(bar3.type == pci::PciBarType::IoSpace, "GPU BAR3 must be I/O Space");
    TEST_ASSERT(bar3.size == 128, "GPU BAR3 size must be 128 bytes");
    TEST_ASSERT((bar3.toRawLow() & 0x01) == 0x01, "I/O BAR must have bit 0 set to 1");

    // Stage 3: Multi-Bus Topology Enumeration & Device Discovery
    TEST_ASSERT(pciSub.getBusCount() >= 4, "PCI subsystem must manage at least 4 active buses (Buses 0..3)");
    auto allDevs = pciSub.getAllDevices();
    TEST_ASSERT(allDevs.size() >= 8, "PCI subsystem must discover at least 8 endpoints and bridges");

    // Verify Root Complex Host Bridge (00:00.0)
    auto hostBridge = pciSub.findDevice(pci::PciAddress(0, 0, 0));
    TEST_ASSERT(hostBridge != nullptr, "Host Bridge at 00:00.0 must exist");
    TEST_ASSERT(hostBridge->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Bridge), "Host Bridge class must be Bridge");

    // Verify PCIe Root Port 1 (00:01.0 -> Bus 1)
    auto rp1 = pciSub.findDevice(pci::PciAddress(0, 1, 0));
    TEST_ASSERT(rp1 != nullptr && rp1->isBridge(), "Root Port 1 at 00:01.0 must be a Type 1 Bridge");
    TEST_ASSERT(rp1->readConfigByte(pci::PCI_CONFIG_SECONDARY_BUS) == 1, "Root Port 1 secondary bus must be 1");

    // Stage 4: Standard Capability Linked-List Traversal
    uint8_t capPtr = gpu->readConfigByte(pci::PCI_CONFIG_CAPABILITIES_PTR);
    TEST_ASSERT(capPtr > 0, "Capabilities pointer at 0x34 must be non-zero");

    bool foundPcieCap = false;
    bool foundMsixCap = false;
    uint8_t currCap = capPtr;
    int maxHops = 16;
    while (currCap != 0 && maxHops-- > 0) {
        uint8_t capId = gpu->readConfigByte(currCap);
        if (capId == pci::PCI_CAP_ID_EXP) foundPcieCap = true;
        if (capId == pci::PCI_CAP_ID_MSIX) foundMsixCap = true;
        currCap = gpu->readConfigByte(currCap + 1);
    }
    TEST_ASSERT(foundPcieCap, "PCI Express Capability (0x10) must be discovered in linked list");
    TEST_ASSERT(foundMsixCap, "MSI-X Capability (0x11) must be discovered in linked list");

    // Stage 5: PCI Express Capability Structure & Link Negotiation
    TEST_ASSERT(gpu->hasPcieCap(), "GPU must report PCIe Capability");
    TEST_ASSERT(gpu->getLinkSpeed() == pci::PciLinkSpeed::Gen5_32_0GT, "PrismX GPU must negotiate PCIe Gen 5 (32 GT/s)");
    TEST_ASSERT(gpu->getLinkWidth() == pci::PciLinkWidth::x16, "PrismX GPU must negotiate PCIe x16 link width");
    TEST_ASSERT(gpu->getLinkSpeedString() == "Gen 5 (32.0 GT/s)", "Link speed string formatting must match");
    TEST_ASSERT(gpu->getLinkWidthString() == "x16", "Link width string formatting must match");

    // Stage 6: Message Signaled Interrupts (MSI) Configuration
    auto xhciDev = pciSub.findDevice(pci::PciAddress(3, 0, 0));
    TEST_ASSERT(xhciDev != nullptr, "TitanUSB xHCI controller 03:00.0 must exist");
    const auto& msi = xhciDev->getMsi();
    TEST_ASSERT(msi.offset > 0, "TitanUSB xHCI must support MSI capability");
    TEST_ASSERT(msi.multiMessageCapable == 3, "TitanUSB xHCI must support 8 MSI vectors (2^3)");

    win32::BOOL bMsiCfg = pci::PciConfigureMsi(xhciDev->getAddress().toBdf(), 0xFEE00000ULL, 0x60, 3);
    TEST_ASSERT(bMsiCfg == win32::TRUE, "PciConfigureMsi must succeed for xHCI");
    TEST_ASSERT(xhciDev->getMsi().enabled, "MSI must be enabled after configuration");
    TEST_ASSERT(xhciDev->getMsi().messageAddress == 0xFEE00000ULL, "MSI target address must match");

    // Stage 7: MSI-X Architecture & Table Programming
    auto nvmeDev = pciSub.findDevice(pci::PciAddress(2, 0, 0));
    TEST_ASSERT(nvmeDev != nullptr, "TitanNVMe controller 02:00.0 must exist");
    const auto& msix = nvmeDev->getMsix();
    TEST_ASSERT(msix.offset > 0, "TitanNVMe must support MSI-X capability");
    TEST_ASSERT(msix.tableSize == 64, "TitanNVMe MSI-X table must have 64 vectors");

    // Program MSI-X Vector 0 (Unmasked)
    win32::BOOL bMsixCfg0 = pci::PciConfigureMsix(nvmeDev->getAddress().toBdf(), 0, 0xFEE00000ULL, 0x40, win32::FALSE);
    TEST_ASSERT(bMsixCfg0 == win32::TRUE, "PciConfigureMsix for vector 0 must succeed");
    TEST_ASSERT(nvmeDev->getMsix().enabled, "MSI-X must be enabled");

    // Trigger Vector 0 -> should deliver immediately
    win32::BOOL bDelivered = pci::PciTriggerMsiVector(nvmeDev->getAddress().toBdf(), 0);
    TEST_ASSERT(bDelivered == win32::TRUE, "Unmasked MSI-X vector trigger must deliver immediately");

    // Program MSI-X Vector 1 (Masked)
    win32::BOOL bMsixCfg1 = pci::PciConfigureMsix(nvmeDev->getAddress().toBdf(), 1, 0xFEE00000ULL, 0x41, win32::TRUE);
    TEST_ASSERT(bMsixCfg1 == win32::TRUE, "PciConfigureMsix for vector 1 must succeed");
    win32::BOOL bMaskedTrig = pci::PciTriggerMsiVector(nvmeDev->getAddress().toBdf(), 1);
    TEST_ASSERT(bMaskedTrig == win32::FALSE, "Masked MSI-X vector trigger must not deliver immediately");
    TEST_ASSERT((nvmeDev->getMsix().pbaBits[0] & 0x02) != 0, "MSI-X PBA bit 1 must be set for pending interrupt");

    // Stage 8: PCIe Extended Capabilities Linked-List Traversal (offset >= 0x100)
    TEST_ASSERT(gpu->getAer().offset >= 0x100, "AER extended capability offset must be >= 0x100 in 4KB config space");
    TEST_ASSERT(gpu->readConfigWord(gpu->getAer().offset) == pci::PCIE_EXT_CAP_ID_AER, "Extended capability ID at offset must be AER (0x0001)");

    // Stage 9: Advanced Error Reporting (AER) Logging & Severity Classification
    uint32_t bdfGpu = gpu->getAddress().toBdf();
    pci::PciInjectAerError(bdfGpu, pci::aer::AER_CORR_BAD_TLP, win32::FALSE, win32::FALSE);
    TEST_ASSERT((gpu->getAer().corrStatus & pci::aer::AER_CORR_BAD_TLP) != 0, "AER correctable Bad TLP status must be recorded");
    TEST_ASSERT(gpu->getAer().totalCorrectableErrors == 1, "Total correctable error count must be 1");

    pci::PciInjectAerError(bdfGpu, pci::aer::AER_UNCORR_POISONED_TLP, win32::TRUE, win32::TRUE);
    TEST_ASSERT((gpu->getAer().uncorrStatus & pci::aer::AER_UNCORR_POISONED_TLP) != 0, "AER uncorrectable Poisoned TLP must be recorded");
    TEST_ASSERT((gpu->getAer().uncorrSeverity & pci::aer::AER_UNCORR_POISONED_TLP) != 0, "AER error severity must be marked Fatal");
    TEST_ASSERT(gpu->getAer().totalFatalErrors == 1, "Total fatal error count must be 1");

    win32::BOOL bAerClr = pci::PciClearAerStatus(bdfGpu);
    TEST_ASSERT(bAerClr == win32::TRUE, "PciClearAerStatus must succeed");
    TEST_ASSERT(gpu->getAer().uncorrStatus == 0, "AER uncorrectable status must be zero after clear");
    TEST_ASSERT(gpu->getAer().corrStatus == 0, "AER correctable status must be zero after clear");

    // Stage 10: Single Root I/O Virtualization (SR-IOV) Metadata & Simulation
    auto nicDev = pciSub.findDevice(pci::PciAddress(0, 4, 0));
    TEST_ASSERT(nicDev != nullptr, "RazzleNet 10GbE controller 00:04.0 must exist");
    nicDev->addSriovCapability(0x200, 64, 0x1565);
    const auto& sriov = nicDev->getSriov();
    TEST_ASSERT(sriov.offset == 0x200, "SR-IOV capability offset must match");
    TEST_ASSERT(sriov.totalVfs == 64, "SR-IOV total VFs must be 64");
    TEST_ASSERT(sriov.vfDeviceId == 0x1565, "SR-IOV VF Device ID must match");

    // Stage 11: Dynamic Loader Module Exports in pci.sys
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("pci.sys", "PciReadConfigByte") != nullptr, "pci.sys PciReadConfigByte export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciReadConfigDword") != nullptr, "pci.sys PciReadConfigDword export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciWriteConfigDword") != nullptr, "pci.sys PciWriteConfigDword export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciFindDevice") != nullptr, "pci.sys PciFindDevice export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciGetBarInfo") != nullptr, "pci.sys PciGetBarInfo export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciEnableBusMastering") != nullptr, "pci.sys PciEnableBusMastering export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciConfigureMsi") != nullptr, "pci.sys PciConfigureMsi export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciConfigureMsix") != nullptr, "pci.sys PciConfigureMsix export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciTriggerMsiVector") != nullptr, "pci.sys PciTriggerMsiVector export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciInjectAerError") != nullptr, "pci.sys PciInjectAerError export must be registered");

    // Stage 12: System Services & Driver Registration
    auto pciSvc = scm::ServiceControlManager::get().getServiceRecord(L"pci");
    TEST_ASSERT(pciSvc != nullptr, "pci service record must exist in SCM");
    TEST_ASSERT(pciSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "pci service type must be kernel driver");
    TEST_ASSERT(pciSvc->startType == scm::SERVICE_BOOT_START, "pci service start type must be boot start");

    auto pciVer = version::VersionDatabase::Instance().GetModuleInfo("pci.sys");
    TEST_ASSERT(pciVer != nullptr, "pci.sys must be registered in Version Database");
    TEST_ASSERT(pciVer->stringTable.count("FileVersion") > 0, "pci.sys FileVersion must exist");

    std::cout << "[TEST] Suite 152: PCI Express (PCIe 5.0) Bus, Root Complex & AER Subsystem PASSED.\n";
}

void Test_MicrosoftPluton_SecurityProcessor_Subsystem() {
    std::cout << "[TEST] Starting Suite 167: Microsoft Pluton Security Processor Subsystem...\n";

    // Stage 1: Subsystem Initialization & Version Query
    micant::pluton::InitializePlutonSubsystem();
    auto& plutonSub = micant::pluton::TitanPlutonSubsystem::Instance();
    TEST_ASSERT(plutonSub.isInitialized(), "Pluton subsystem must be initialized");
    uint32_t ver = micant::pluton::PlutonGetVersion();
    TEST_ASSERT(ver == micant::pluton::PLUTON_VERSION_1_0, "Pluton version must be 1.0 (0x00010000)");

    // Stage 2: Hardware Processor Model & Capabilities
    char modelBuf[128]{};
    char fwBuf[64]{};
    uint32_t opMode = 0;
    NTSTATUS capStatus = micant::pluton::PlutonGetCapabilities(modelBuf, sizeof(modelBuf), fwBuf, sizeof(fwBuf), &opMode);
    TEST_ASSERT(capStatus == STATUS_SUCCESS, "PlutonGetCapabilities must return STATUS_SUCCESS");
    TEST_ASSERT(std::string(modelBuf).find("Pluton Security Subsystem") != std::string::npos, "Model string must identify Pluton");
    TEST_ASSERT(std::string(fwBuf).find("PLTN") != std::string::npos, "Firmware version must contain PLTN marker");
    TEST_ASSERT(opMode == static_cast<uint32_t>(micant::pluton::PlutonMode::Tpm2_Emulation), "Default mode must be TPM 2.0 emulation");

    // Stage 3: PCR Initial State Verification
    uint8_t pcr0[32]{};
    uint8_t pcr7[32]{};
    uint8_t pcr11[32]{};
    TEST_ASSERT(micant::pluton::PlutonReadPcr(0, pcr0) == STATUS_SUCCESS, "Read PCR 0 (Firmware) must succeed");
    TEST_ASSERT(micant::pluton::PlutonReadPcr(7, pcr7) == STATUS_SUCCESS, "Read PCR 7 (Secure Boot) must succeed");
    TEST_ASSERT(micant::pluton::PlutonReadPcr(11, pcr11) == STATUS_SUCCESS, "Read PCR 11 (BitLocker Policy) must succeed");
    TEST_ASSERT(pcr0[0] == 0xAA && pcr0[31] == 0x01, "PCR 0 initial measurement mismatch");
    TEST_ASSERT(pcr7[0] == 0x5E && pcr7[31] == 0x07, "PCR 7 Secure Boot initial state mismatch");
    TEST_ASSERT(pcr11[0] == 0xBC && pcr11[31] == 0x0B, "PCR 11 BitLocker initial state mismatch");

    // Stage 4: PCR Measurement Extension
    const uint8_t bootMeasurement[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                          0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    uint8_t pcr14Before[32]{};
    uint8_t pcr14After[32]{};
    micant::pluton::PlutonReadPcr(14, pcr14Before);
    NTSTATUS extStatus = micant::pluton::PlutonExtendPcr(14, bootMeasurement, sizeof(bootMeasurement));
    TEST_ASSERT(extStatus == STATUS_SUCCESS, "PlutonExtendPcr on PCR 14 must return STATUS_SUCCESS");
    micant::pluton::PlutonReadPcr(14, pcr14After);
    TEST_ASSERT(std::memcmp(pcr14Before, pcr14After, 32) != 0, "PCR 14 digest must change after measurement extension");

    // Stage 5: Hardware True Random Number Generator (TRNG)
    uint8_t rndBuf1[32]{};
    uint8_t rndBuf2[32]{};
    TEST_ASSERT(micant::pluton::PlutonGenerateRandom(sizeof(rndBuf1), rndBuf1) == STATUS_SUCCESS, "TRNG generation 1 must succeed");
    TEST_ASSERT(micant::pluton::PlutonGenerateRandom(sizeof(rndBuf2), rndBuf2) == STATUS_SUCCESS, "TRNG generation 2 must succeed");
    TEST_ASSERT(std::memcmp(rndBuf1, rndBuf2, 32) != 0, "Sequential TRNG generations must produce distinct random streams");

    // Stage 6: Enclave Keystore Inspection
    auto keystore = plutonSub.getKeystore();
    TEST_ASSERT(keystore.size() >= 3, "Hardware keystore must have at least 3 pre-seeded root keys");
    bool foundSrk = false, foundEk = false, foundVmk = false;
    for (const auto& k : keystore) {
        if (k.keyId == 1 && k.algorithm == "ECC-P384") foundSrk = true;
        if (k.keyId == 2 && k.algorithm == "RSA-4096") foundEk = true;
        if (k.keyId == 3 && k.algorithm == "AES-256-GCM") foundVmk = true;
    }
    TEST_ASSERT(foundSrk, "Storage Root Key (SRK ECC-P384) must be in keystore");
    TEST_ASSERT(foundEk, "Endorsement Key (EK RSA-4096) must be in keystore");
    TEST_ASSERT(foundVmk, "BitLocker Volume Master Key (VMK-Sealed AES-256-GCM) must be in keystore");

    // Stage 7: Hardware-Assisted Data Sealing
    const uint8_t secretKey[32] = { "MicaNT_UltraSecure_BitLocker_K" };
    uint32_t boundPcrMask = (1 << 7) | (1 << 11); // Bound to PCR 7 (Secure Boot) and PCR 11 (BitLocker)
    uint32_t blobId = 0;
    uint32_t sealLatNs = 0;
    NTSTATUS sealStatus = micant::pluton::PlutonSealData(boundPcrMask, secretKey, sizeof(secretKey), &blobId, &sealLatNs);
    TEST_ASSERT(sealStatus == STATUS_SUCCESS, "PlutonSealData must return STATUS_SUCCESS");
    TEST_ASSERT(blobId >= 1001, "Sealed blob ID must be >= 1001");
    TEST_ASSERT(sealLatNs > 0 && sealLatNs < 50000, "Pluton seal latency must be low (<50us)");

    // Stage 8: Authorized Unsealing with Matching PCR State
    uint8_t unsealedPayload[64]{};
    size_t unsealedLen = 0;
    uint32_t unsealLatNs = 0;
    NTSTATUS unsealStatus = micant::pluton::PlutonUnsealData(blobId, unsealedPayload, &unsealedLen, &unsealLatNs);
    TEST_ASSERT(unsealStatus == STATUS_SUCCESS, "PlutonUnsealData must succeed with matching PCR state");
    TEST_ASSERT(std::memcmp(secretKey, unsealedPayload, sizeof(secretKey)) == 0, "Unsealed payload must match original plaintext");

    // Stage 9: Tamper Simulation & Anti-Tamper PCR Invalidation
    const uint8_t tamperPayload[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    micant::pluton::PlutonExtendPcr(7, tamperPayload, sizeof(tamperPayload));

    // Stage 10: Unauthorized Unsealing Rejection
    uint8_t tamperedPayloadOut[64]{};
    size_t tamperedLenOut = 0;
    NTSTATUS rejectStatus = micant::pluton::PlutonUnsealData(blobId, tamperedPayloadOut, &tamperedLenOut, nullptr);
    TEST_ASSERT(rejectStatus == STATUS_ACCESS_DENIED, "Unsealing must be rejected with STATUS_ACCESS_DENIED after PCR state change");

    // Stage 11: Multi-PCR Policy Bitmask Sealing
    const uint8_t adminToken[16] = { 0x55, 0xAA, 0x55, 0xAA, 0x11, 0x22, 0x33, 0x44,
                                     0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x32, 0x10 };
    uint32_t multiPcrMask = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3); // PCR 0..3
    uint32_t multiBlobId = 0;
    TEST_ASSERT(micant::pluton::PlutonSealData(multiPcrMask, adminToken, sizeof(adminToken), &multiBlobId, nullptr) == STATUS_SUCCESS,
                "Multi-PCR sealing must succeed");
    uint8_t multiPlain[64]{};
    size_t multiPlainLen = 0;
    TEST_ASSERT(micant::pluton::PlutonUnsealData(multiBlobId, multiPlain, &multiPlainLen, nullptr) == STATUS_SUCCESS,
                "Multi-PCR unsealing must succeed before state changes");
    TEST_ASSERT(std::memcmp(adminToken, multiPlain, sizeof(adminToken)) == 0, "Multi-PCR unsealed data must match");

    // Stage 12: Invalid Parameter Boundaries
    TEST_ASSERT(micant::pluton::PlutonReadPcr(micant::pluton::PLUTON_PCR_COUNT, pcr0) == STATUS_INVALID_PARAMETER, "Reading out-of-range PCR must fail");
    TEST_ASSERT(micant::pluton::PlutonReadPcr(0, nullptr) == STATUS_INVALID_PARAMETER, "Reading into nullptr buffer must fail");
    TEST_ASSERT(micant::pluton::PlutonExtendPcr(99, bootMeasurement, 16) == STATUS_INVALID_PARAMETER, "Extending invalid PCR must fail");
    TEST_ASSERT(micant::pluton::PlutonExtendPcr(0, nullptr, 16) == STATUS_INVALID_PARAMETER, "Extending with nullptr digest must fail");
    uint8_t oversized[128]{};
    uint32_t invalidBlob = 0;
    TEST_ASSERT(micant::pluton::PlutonSealData(1, oversized, sizeof(oversized), &invalidBlob, nullptr) == STATUS_INSUFFICIENT_RESOURCES,
                "Oversized payload sealing (>64 bytes) must fail");
    TEST_ASSERT(micant::pluton::PlutonSealData(1, nullptr, 16, &invalidBlob, nullptr) == STATUS_INVALID_PARAMETER, "Sealing nullptr must fail");
    TEST_ASSERT(micant::pluton::PlutonGenerateRandom(0, rndBuf1) == STATUS_INVALID_PARAMETER, "Zero-length TRNG request must fail");
    TEST_ASSERT(micant::pluton::PlutonGenerateRandom(16, nullptr) == STATUS_INVALID_PARAMETER, "Nullptr buffer TRNG request must fail");

    // Stage 13: Hardware Execution Latency & Bus Sniff Immunity Telemetry
    micant::pluton::PlutonTelemetry telem{};
    NTSTATUS telemStatus = micant::pluton::PlutonGetTelemetry(&telem);
    TEST_ASSERT(telemStatus == STATUS_SUCCESS, "PlutonGetTelemetry must return STATUS_SUCCESS");
    TEST_ASSERT(telem.physicalBusSniffImmune == true, "Pluton must assert on-die physical bus-sniffing immunity");
    TEST_ASSERT(telem.trngHealthy == true, "Pluton TRNG must be healthy");
    TEST_ASSERT(telem.totalCommandsExecuted > 5, "Total executed commands must reflect test operations");
    TEST_ASSERT(telem.totalPcrExtends >= 2, "Telemetry must record at least 2 PCR extend operations");
    TEST_ASSERT(telem.totalSealOperations >= 2, "Telemetry must record at least 2 seal operations");
    TEST_ASSERT(telem.avgCommandLatencyNs < 10000, "Average command latency must be on-die scale (<10us)");

    // Stage 14: Dynamic Loader C ABI Symbol Resolution
    auto& ldr = micant::ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("pluton.sys", "PlutonInitialize") != nullptr, "pluton.sys!PlutonInitialize must be exported");
    TEST_ASSERT(ldr.getExport("pluton.sys", "PlutonGetCapabilities") != nullptr, "pluton.sys!PlutonGetCapabilities must be exported");
    TEST_ASSERT(ldr.getExport("pluton.sys", "PlutonReadPcr") != nullptr, "pluton.sys!PlutonReadPcr must be exported");
    TEST_ASSERT(ldr.getExport("pluton.sys", "PlutonExtendPcr") != nullptr, "pluton.sys!PlutonExtendPcr must be exported");
    TEST_ASSERT(ldr.getExport("pluton.sys", "PlutonSealData") != nullptr, "pluton.sys!PlutonSealData must be exported");
    TEST_ASSERT(ldr.getExport("pluton.sys", "PlutonUnsealData") != nullptr, "pluton.sys!PlutonUnsealData must be exported");
    TEST_ASSERT(ldr.getExport("pluton.sys", "PlutonGenerateRandom") != nullptr, "pluton.sys!PlutonGenerateRandom must be exported");
    TEST_ASSERT(ldr.getExport("pluton.sys", "PlutonGetTelemetry") != nullptr, "pluton.sys!PlutonGetTelemetry must be exported");

    // Stage 15: Service Control Manager (SCM) Registration
    auto plutonSvc = micant::scm::ServiceControlManager::get().getServiceRecord(L"pluton");
    TEST_ASSERT(plutonSvc != nullptr, "pluton service record must exist in SCM");
    TEST_ASSERT(plutonSvc->serviceType == micant::scm::SERVICE_KERNEL_DRIVER, "pluton must be registered as SERVICE_KERNEL_DRIVER");
    TEST_ASSERT(plutonSvc->startType == micant::scm::SERVICE_BOOT_START, "pluton must be configured as SERVICE_BOOT_START");
    TEST_ASSERT(plutonSvc->status.dwCurrentState == micant::scm::SERVICE_RUNNING, "pluton driver state must be SERVICE_RUNNING");

    // Stage 16: Version Database Module Registration
    const auto* modPluton = micant::version::VersionDatabase::Instance().GetModuleInfo("pluton.sys");
    TEST_ASSERT(modPluton != nullptr, "pluton.sys must be registered in VersionDatabase");
    TEST_ASSERT(modPluton->stringTable.at("ProductVersion") == "10.0.26100.1", "pluton.sys version must match 10.0.26100.1");

    std::cout << "[TEST] Suite 167: Microsoft Pluton Security Processor Subsystem PASSED.\n";
}

void Test_PersistentMemory_NVDIMM_Optane_DAX_Subsystem() {
    std::cout << "[TEST] Starting Suite 165: Persistent Memory (NVDIMM / Intel Optane PMEM) & DAX Storage Subsystem...\n";

    // Stage 1: Subsystem Initialization & Version Check
    pmem::InitializePmemSubsystem();
    auto& pmemSub = pmem::TitanPmemSubsystem::Instance();
    TEST_ASSERT(pmemSub.isInitialized(), "PMEM subsystem must be initialized");
    uint32_t ver = pmem::PmemGetVersion();
    TEST_ASSERT(ver == 0x00010000, "PMEM driver version must be 1.0 (0x00010000)");

    // Stage 2: Physical NVDIMM Module Enumeration (Intel Optane PMEM 300 Series)
    uint32_t devCount = pmem::PmemGetDeviceCount();
    TEST_ASSERT(devCount == 2, "Must enumerate 2 physical Optane PMEM modules");
    pmem::PmemNvdimmDevice dev1{};
    NTSTATUS dev1St = pmem::PmemGetDeviceInfo(1, &dev1);
    TEST_ASSERT(dev1St == STATUS_SUCCESS, "Retrieving device 1 info must succeed");
    TEST_ASSERT(dev1.modelNumber.find("Optane") != std::string::npos, "Device 1 must be an Intel Optane PMEM module");
    TEST_ASSERT(dev1.capacityBytes == 512ULL * 1024ULL * 1024ULL * 1024ULL, "Device 1 must have 512 GB capacity");
    TEST_ASSERT(dev1.health == pmem::PmemHealthStatus::Healthy, "Device 1 health status must be Healthy");
    TEST_ASSERT(dev1.adrBatteryBacked, "Device 1 must support Asynchronous DRAM Refresh (ADR) battery backup");

    pmem::PmemNvdimmDevice dev2{};
    NTSTATUS dev2St = pmem::PmemGetDeviceInfo(2, &dev2);
    TEST_ASSERT(dev2St == STATUS_SUCCESS, "Retrieving device 2 info must succeed");
    TEST_ASSERT(dev2.capacityBytes == 512ULL * 1024ULL * 1024ULL * 1024ULL, "Device 2 must have 512 GB capacity");

    // Stage 3: Logical PMEM Pool Discovery (App Direct & BTT)
    uint32_t poolCount = pmem::PmemGetPoolCount();
    TEST_ASSERT(poolCount == 2, "Must discover 2 logical PMEM pools");
    pmem::PmemPool pool1{};
    NTSTATUS pool1St = pmem::PmemGetPoolInfo(1, &pool1);
    TEST_ASSERT(pool1St == STATUS_SUCCESS, "Retrieving pool 1 info must succeed");
    TEST_ASSERT(pool1.mode == pmem::PmemOperatingMode::AppDirect_DAX, "Pool 1 must be configured for App Direct DAX mode");
    TEST_ASSERT(pool1.totalCapacityBytes == 1024ULL * 1024ULL * 1024ULL * 1024ULL, "Pool 1 capacity must be 1 TB");
    TEST_ASSERT(pool1.interleaveWays == 2, "Pool 1 must be 2-way interleaved across modules");
    TEST_ASSERT(pool1.interleaveLineSize == 256, "Pool 1 interleave line size must be 256 bytes");

    pmem::PmemPool pool2{};
    NTSTATUS pool2St = pmem::PmemGetPoolInfo(2, &pool2);
    TEST_ASSERT(pool2St == STATUS_SUCCESS, "Retrieving pool 2 info must succeed");
    TEST_ASSERT(pool2.mode == pmem::PmemOperatingMode::Sector_BTT, "Pool 2 must be configured for Block Translation Table mode");
    TEST_ASSERT(pool2.totalCapacityBytes == 128ULL * 1024ULL * 1024ULL * 1024ULL, "Pool 2 capacity must be 128 GB");

    // Stage 4: App Direct DAX Userland Memory Mapping Allocation
    uint64_t mapId = 0;
    uint64_t virtAddr = 0;
    NTSTATUS mapSt = pmem::DaxMapFileToMemory("C:\\Data\\HighFrequencyOrderBook.dat", 64ULL * 1024ULL * 1024ULL, 1, &mapId, &virtAddr);
    TEST_ASSERT(mapSt == STATUS_SUCCESS, "DaxMapFileToMemory must succeed");
    TEST_ASSERT(mapId >= 5001, "Valid DAX mapping ID must be allocated");

    // Stage 5: Zero-Copy Virtual Address Window Assignment
    TEST_ASSERT(virtAddr == 0x7FFF00000000ULL, "DAX virtual address must be mapped into the 64-bit userland DAX window");
    auto activeMappings = pmemSub.getActiveDaxMappings();
    TEST_ASSERT(!activeMappings.empty(), "Active DAX mappings list must contain the new mapping");

    // Stage 6: Cache Line Write-Back & Persistence Barrier Flush (clwb + sfence)
    uint32_t flushLatNs = 0;
    NTSTATUS flushSt = pmem::PmemFlushCacheLine(mapId, 0, 64, &flushLatNs);
    TEST_ASSERT(flushSt == STATUS_SUCCESS, "PmemFlushCacheLine must succeed for a 64-byte cache line");

    // Stage 7: Sub-100 Nanosecond Persistence Flush Latency Verification
    TEST_ASSERT(flushLatNs < 100, "Persistence flush latency must be sub-100 nanoseconds (< 100ns)");

    // Stage 8: Read, Write & Flush Latency Verification
    pmem::PmemTelemetry telem{};
    NTSTATUS telemSt = pmem::PmemGetTelemetry(&telem);
    TEST_ASSERT(telemSt == STATUS_SUCCESS, "Telemetry query must succeed");
    TEST_ASSERT(telem.avgReadLatencyNs < 300, "App Direct read latency must be sub-300ns (~210ns)");
    TEST_ASSERT(telem.avgWriteLatencyNs < 250, "App Direct write latency must be sub-250ns (~180ns)");
    TEST_ASSERT(telem.avgFlushLatencyNs < 100, "Hardware flush barrier latency must be sub-100ns (~85ns)");

    // Stage 9: Block Translation Table (BTT) Atomic 4KB Sector Update
    uint64_t prevWritten = telem.totalBytesWritten;
    uint64_t prevFlushes = telem.totalCacheLineFlushes;
    uint8_t dummySector[4096]{};
    dummySector[0] = 0xAA;
    dummySector[4095] = 0x55;
    bool bttOk = pmemSub.writeBttAtomicSector(2, 100, dummySector);
    TEST_ASSERT(bttOk, "BTT atomic sector write must succeed on Pool 2");
    pmem::PmemGetTelemetry(&telem);
    TEST_ASSERT(telem.totalBytesWritten == prevWritten + 4096, "BTT write must update written telemetry by 4096 bytes");
    TEST_ASSERT(telem.totalCacheLineFlushes == prevFlushes + 64, "BTT 4KB atomic sector write must flush 64 cache lines");

    // Stage 10: Asynchronous DRAM Refresh (ADR) Power Protection Circuit Status
    TEST_ASSERT(telem.adrProtectionArmActive, "Asynchronous DRAM Refresh (ADR) circuit must be armed and active");

    // Stage 11: DAX Unmap Operation & Capacity Reclamation
    uint64_t beforeAlloc = pmemSub.getPool(1)->allocatedBytes;
    NTSTATUS unmapSt = pmem::DaxUnmapFile(mapId);
    TEST_ASSERT(unmapSt == STATUS_SUCCESS, "DaxUnmapFile must successfully release the DAX mapping");
    uint64_t afterAlloc = pmemSub.getPool(1)->allocatedBytes;
    TEST_ASSERT(afterAlloc < beforeAlloc, "Pool allocated bytes must be reclaimed upon unmapping");

    // Stage 12: Rejection of Out-of-Bounds Cache Line Flush
    uint32_t badLat = 0;
    NTSTATUS badFlushSt = pmem::PmemFlushCacheLine(mapId, 0x10000000, 64, &badLat);
    TEST_ASSERT(badFlushSt != STATUS_SUCCESS, "Out-of-bounds or invalid mapping flush must be rejected");

    // Stage 13: ACPI NFIT Range Descriptor Validation
    TEST_ASSERT(pmem::ACPI_NFIT_SIGNATURE == 0x5449464E, "ACPI NFIT signature must match 'NFIT'");
    TEST_ASSERT(pmem::SEC_DAX == 0x02000000, "SEC_DAX allocation flag must match Win32 specification (0x02000000)");
    TEST_ASSERT(pmem::GUID_PMEM_BYTE_ADDRESSABLE.data1 == 0x7305944f, "App Direct byte-addressable GUID data1 must match standard");
    TEST_ASSERT(pmem::GUID_PMEM_BLOCK_TRANSLATION_TABLE.data1 == 0x1928cdab, "BTT sector GUID data1 must match standard");

    // Stage 14: Driver C ABI Exports Verification (pmem.sys & dax.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemInitialize") != nullptr, "PmemInitialize export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetVersion") != nullptr, "PmemGetVersion export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetDeviceCount") != nullptr, "PmemGetDeviceCount export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetDeviceInfo") != nullptr, "PmemGetDeviceInfo export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetPoolCount") != nullptr, "PmemGetPoolCount export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetPoolInfo") != nullptr, "PmemGetPoolInfo export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemFlushCacheLine") != nullptr, "PmemFlushCacheLine export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetTelemetry") != nullptr, "PmemGetTelemetry export must exist");
    TEST_ASSERT(ldr.getExport("dax.sys", "DaxMapFileToMemory") != nullptr, "DaxMapFileToMemory export must exist");
    TEST_ASSERT(ldr.getExport("dax.sys", "DaxUnmapFile") != nullptr, "DaxUnmapFile export must exist");

    // Stage 15: SCM Driver Service Registrations (pmem.sys & dax.sys)
    auto pmemSvc = scm::ServiceControlManager::get().getServiceRecord(L"pmem");
    TEST_ASSERT(pmemSvc != nullptr, "pmem service record must exist in SCM");
    TEST_ASSERT(pmemSvc->startType == scm::SERVICE_BOOT_START, "pmem must be configured with SERVICE_BOOT_START");

    auto daxSvc = scm::ServiceControlManager::get().getServiceRecord(L"dax");
    TEST_ASSERT(daxSvc != nullptr, "dax service record must exist in SCM");
    TEST_ASSERT(daxSvc->startType == scm::SERVICE_SYSTEM_START, "dax must be configured with SERVICE_SYSTEM_START");

    // Stage 16: Version Database Registration Verification
    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("pmem.sys") != nullptr, "pmem.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("dax.sys") != nullptr, "dax.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 165: Persistent Memory (NVDIMM / Intel Optane PMEM) & DAX Storage Subsystem PASSED.\n";
}

void Test_IntelQAT_HardwareOffload_Subsystem() {
    std::cout << "[TEST] Starting Suite 170: Intel QuickAssist Technology (QAT) Hardware Offload Subsystem...\n";

    // Stage 1: Subsystem Registration & Initialization
    micant::qat::RegisterQatSubsystem();
    auto& qatSub = micant::qat::TitanQatSubsystem::get();
    bool initOk = qatSub.initialize();
    TEST_ASSERT(initOk, "TitanQatSubsystem initialization must succeed");
    TEST_ASSERT(qatSub.isInitialized(), "TitanQatSubsystem must report initialized state");

    // Stage 2: Hardware Capabilities Check
    auto caps = qatSub.getCapabilities();
    TEST_ASSERT(caps.hasSymCrypto == true, "QAT Symmetric Cryptography capability must be true");
    TEST_ASSERT(caps.hasAsymCrypto == true, "QAT Asymmetric Cryptography capability must be true");
    TEST_ASSERT(caps.hasCompression == true, "QAT Data Compression capability must be true");
    TEST_ASSERT(caps.hasSriov == true, "QAT SR-IOV Virtualization must be supported");
    TEST_ASSERT(caps.numEngines == 10, "QAT must report exactly 10 hardware acceleration engines");
    TEST_ASSERT(caps.numVirtualFunctions == 16, "QAT must support 16 SR-IOV Virtual Functions");

    // Stage 3: Hardware Acceleration Engine Verification
    auto engines = qatSub.getEngines();
    TEST_ASSERT(engines.size() == 10, "Engines vector must contain 10 entries");
    TEST_ASSERT(engines[0].type == micant::qat::QatEngineType::SymmetricCrypto, "Engine 0 must be Symmetric Crypto");
    TEST_ASSERT(engines[4].type == micant::qat::QatEngineType::AsymmetricCrypto, "Engine 4 must be Asymmetric Crypto");
    TEST_ASSERT(engines[6].type == micant::qat::QatEngineType::DataCompression, "Engine 6 must be Data Compression");

    // Stage 4: Symmetric Encryption Offload (AES-256-XTS)
    const char* plainText = "Dave Cutler Clean-Room Executive Kernel Persistent Block Data";
    uint32_t inLen = static_cast<uint32_t>(std::strlen(plainText));
    uint8_t key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                       0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    uint8_t iv[16] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67};
    std::vector<uint8_t> cipher(inLen);
    uint32_t cipherLen = 0;

    bool encOk = qatSub.offloadSymEncrypt(micant::qat::QatCipherAlgo::AesXts256,
        reinterpret_cast<const uint8_t*>(plainText), inLen, key, sizeof(key), iv, cipher.data(), &cipherLen);
    TEST_ASSERT(encOk, "Hardware offload of AES-256-XTS encryption must succeed");
    TEST_ASSERT(cipherLen == inLen, "Ciphertext length must equal plaintext length");

    // Stage 5: Symmetric Decryption Offload Verification
    std::vector<uint8_t> decrypted(cipherLen);
    uint32_t decLen = 0;
    bool decOk = qatSub.offloadSymDecrypt(micant::qat::QatCipherAlgo::AesXts256,
        cipher.data(), cipherLen, key, sizeof(key), iv, decrypted.data(), &decLen);
    TEST_ASSERT(decOk, "Hardware offload of AES-256-XTS decryption must succeed");
    TEST_ASSERT(decLen == inLen, "Decrypted length must match original length");
    std::string recovered(decrypted.begin(), decrypted.begin() + decLen);
    TEST_ASSERT(recovered == plainText, "Decrypted payload must match original plaintext exactly");

    // Stage 6: Symmetric Encryption Offload (AES-256-GCM)
    std::vector<uint8_t> gcmCipher(inLen);
    uint32_t gcmCipherLen = 0;
    bool gcmEncOk = qatSub.offloadSymEncrypt(micant::qat::QatCipherAlgo::AesGcm256,
        reinterpret_cast<const uint8_t*>(plainText), inLen, key, sizeof(key), iv, gcmCipher.data(), &gcmCipherLen);
    TEST_ASSERT(gcmEncOk, "Hardware offload of AES-256-GCM encryption must succeed");

    // Stage 7: Lossless Data Compression Offload (Zstandard / ZSTD)
    std::string compInput = "MicaNT_DirectStorage_GDeflate_Chunk_Payload_0000000000_1111111111_2222222222";
    uint32_t compInLen = static_cast<uint32_t>(compInput.size());
    std::vector<uint8_t> compressed(compInLen + 32);
    uint32_t compLen = 0;
    bool compOk = qatSub.offloadCompress(micant::qat::QatCompAlgo::Zstandard,
        reinterpret_cast<const uint8_t*>(compInput.data()), compInLen, compressed.data(), &compLen);
    TEST_ASSERT(compOk, "Hardware offload of Zstandard compression must succeed");
    TEST_ASSERT(compLen > 4, "Compressed output must contain QAT header and data");
    TEST_ASSERT(compressed[0] == 'Q' && compressed[1] == 'A' && compressed[2] == 'T', "QAT compression header magic must match");

    // Stage 8: Lossless Data Decompression Offload Verification
    std::vector<uint8_t> decompressed(compInLen + 32);
    uint32_t decompLen = 0;
    bool decompOk = qatSub.offloadDecompress(micant::qat::QatCompAlgo::Zstandard,
        compressed.data(), compLen, decompressed.data(), static_cast<uint32_t>(decompressed.size()), &decompLen);
    TEST_ASSERT(decompOk, "Hardware offload of Zstandard decompression must succeed");
    TEST_ASSERT(decompLen == compInLen, "Decompressed length must match original size");
    std::string decompStr(decompressed.begin(), decompressed.begin() + decompLen);
    TEST_ASSERT(decompStr == compInput, "Decompressed string must match original uncompressed text");

    // Stage 9: Lossless Data Compression Offload (Deflate RFC 1951)
    std::vector<uint8_t> defCompressed(compInLen + 32);
    uint32_t defCompLen = 0;
    bool defOk = qatSub.offloadCompress(micant::qat::QatCompAlgo::Deflate,
        reinterpret_cast<const uint8_t*>(compInput.data()), compInLen, defCompressed.data(), &defCompLen);
    TEST_ASSERT(defOk, "Hardware offload of Deflate compression must succeed");

    // Stage 10: Asymmetric Public Key Cryptography (RSA Modular Exponentiation)
    uint8_t modulus[16] = {0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8};
    uint8_t exponent[4] = {0x01, 0x00, 0x01, 0x00};
    uint8_t rsaInput[16] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00};
    uint8_t rsaOutput[16]{};
    uint32_t rsaOutLen = 0;
    bool rsaOk = qatSub.offloadAsymRsa(modulus, sizeof(modulus), exponent, sizeof(exponent),
                                      rsaInput, sizeof(rsaInput), rsaOutput, &rsaOutLen);
    TEST_ASSERT(rsaOk, "Hardware offload of RSA modular exponentiation must succeed");
    TEST_ASSERT(rsaOutLen == sizeof(rsaInput), "RSA transformed output size must match input");

    // Stage 11: SR-IOV Virtual Function Management
    bool vfEnable = qatSub.enableVirtualFunction(5, true);
    TEST_ASSERT(vfEnable, "Enabling SR-IOV Virtual Function 5 must succeed");
    auto telemVf = qatSub.getTelemetry();
    TEST_ASSERT(telemVf.activeVfs >= 5, "Active Virtual Functions count must reflect enabled VF");

    // Stage 12: Telemetry Metrics Verification
    auto telem = qatSub.getTelemetry();
    TEST_ASSERT(telem.symEncryptRequests >= 2, "Telemetry symEncryptRequests must be at least 2");
    TEST_ASSERT(telem.symDecryptRequests >= 1, "Telemetry symDecryptRequests must be at least 1");
    TEST_ASSERT(telem.compCompressRequests >= 2, "Telemetry compCompressRequests must be at least 2");
    TEST_ASSERT(telem.compDecompressRequests >= 1, "Telemetry compDecompressRequests must be at least 1");
    TEST_ASSERT(telem.asymOpsProcessed >= 1, "Telemetry asymOpsProcessed must be at least 1");
    TEST_ASSERT(telem.totalBytesProcessed > 0, "Telemetry totalBytesProcessed must be non-zero");

    // Stage 13: Direct C ABI Calling
    uint32_t cMajor = 0, cMinor = 0, cBuild = 0;
    TEST_ASSERT(micant::qat::QatGetVersion(&cMajor, &cMinor, &cBuild) == 0, "QatGetVersion must return 0");
    TEST_ASSERT(cMajor == 10 && cBuild == 26100, "QAT driver version must report 10.0.26100");

    // Stage 14: Dynamic Loader C ABI Symbol Resolution
    auto& ldr = micant::ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("intel_qat.sys", "QatInitialize") != nullptr, "intel_qat.sys!QatInitialize must be exported");
    TEST_ASSERT(ldr.getExport("intel_qat.sys", "QatGetCapabilities") != nullptr, "intel_qat.sys!QatGetCapabilities must be exported");
    TEST_ASSERT(ldr.getExport("intel_qat.sys", "QatGetTelemetry") != nullptr, "intel_qat.sys!QatGetTelemetry must be exported");
    TEST_ASSERT(ldr.getExport("qat_crypto.sys", "QatEncryptSym") != nullptr, "qat_crypto.sys!QatEncryptSym must be exported");
    TEST_ASSERT(ldr.getExport("qat_crypto.sys", "QatDecryptSym") != nullptr, "qat_crypto.sys!QatDecryptSym must be exported");
    TEST_ASSERT(ldr.getExport("qat_crypto.sys", "QatPerformRsa") != nullptr, "qat_crypto.sys!QatPerformRsa must be exported");
    TEST_ASSERT(ldr.getExport("qat_comp.sys", "QatCompress") != nullptr, "qat_comp.sys!QatCompress must be exported");
    TEST_ASSERT(ldr.getExport("qat_comp.sys", "QatDecompress") != nullptr, "qat_comp.sys!QatDecompress must be exported");

    // Stage 15: Service Control Manager (SCM) Registration
    auto qatSvc = micant::scm::ServiceControlManager::get().getServiceRecord(L"intel_qat");
    TEST_ASSERT(qatSvc != nullptr, "intel_qat service record must exist in SCM");
    TEST_ASSERT(qatSvc->serviceType == micant::scm::SERVICE_KERNEL_DRIVER, "intel_qat must be registered as SERVICE_KERNEL_DRIVER");
    TEST_ASSERT(qatSvc->startType == micant::scm::SERVICE_BOOT_START, "intel_qat must be configured as SERVICE_BOOT_START");
    auto cryptoSvc = micant::scm::ServiceControlManager::get().getServiceRecord(L"qat_crypto");
    TEST_ASSERT(cryptoSvc != nullptr, "qat_crypto service record must exist in SCM");
    TEST_ASSERT(cryptoSvc->startType == micant::scm::SERVICE_SYSTEM_START, "qat_crypto must be configured as SERVICE_SYSTEM_START");
    auto compSvc = micant::scm::ServiceControlManager::get().getServiceRecord(L"qat_comp");
    TEST_ASSERT(compSvc != nullptr, "qat_comp service record must exist in SCM");
    TEST_ASSERT(compSvc->startType == micant::scm::SERVICE_SYSTEM_START, "qat_comp must be configured as SERVICE_SYSTEM_START");

    // Stage 16: Version Database Module Registration
    const auto* modQat = micant::version::VersionDatabase::Instance().GetModuleInfo("intel_qat.sys");
    TEST_ASSERT(modQat != nullptr, "intel_qat.sys must be registered in VersionDatabase");
    TEST_ASSERT(modQat->stringTable.at("ProductVersion") == "10.0.26100.1", "intel_qat.sys version must match 10.0.26100.1");
    const auto* modCrypto = micant::version::VersionDatabase::Instance().GetModuleInfo("qat_crypto.sys");
    TEST_ASSERT(modCrypto != nullptr, "qat_crypto.sys must be registered in VersionDatabase");
    TEST_ASSERT(modCrypto->stringTable.at("ProductVersion") == "10.0.26100.1", "qat_crypto.sys version must match 10.0.26100.1");

    std::cout << "[TEST] Suite 170: Intel QuickAssist Technology (QAT) Hardware Offload Subsystem PASSED.\n";
}

void Test_RDMA_RoCEv2_InfiniBand_SMBDirect_Subsystem() {
    std::cout << "[TEST] Starting Suite 166: Remote Direct Memory Access (RDMA / RoCE v2 & InfiniBand) & SMB Direct Subsystem...\n";

    // Stage 1: Subsystem Initialization & Version Check
    rdma::InitializeRdmaSubsystem();
    auto& rdmaSub = rdma::TitanRdmaSubsystem::Instance();
    TEST_ASSERT(rdmaSub.isInitialized(), "RDMA subsystem must be initialized");
    uint32_t ver = rdma::RdmaGetVersion();
    TEST_ASSERT(ver == 0x00010000, "RDMA version must be 1.0 (0x00010000)");

    // Stage 2: Hardware Host Channel Adapter (HCA) Discovery
    TEST_ASSERT(rdmaSub.getAdapterName().find("RazzleNet-RDMA") != std::string::npos, "HCA adapter name must match RazzleNet-RDMA");
    TEST_ASSERT(rdmaSub.getPcieLocation() == "00:0A.0", "HCA PCIe location must be 00:0A.0");
    TEST_ASSERT(rdmaSub.getTransport() == rdma::RdmaTransportType::RoCE_v2, "Transport technology must default to RoCE v2");
    TEST_ASSERT(rdmaSub.getLinkSpeedBps() == 100ULL * 1000ULL * 1000ULL * 1000ULL, "Link speed must be 100 Gbps");

    // Stage 3: Protection Domain (PD) Allocation
    uint32_t pdId = 0;
    NTSTATUS pdSt = rdma::RdmaCreateProtectionDomain(&pdId);
    TEST_ASSERT(pdSt == STATUS_SUCCESS, "RdmaCreateProtectionDomain must succeed");
    TEST_ASSERT(pdId >= 101, "Allocated Protection Domain ID must be valid");

    // Stage 4: Completion Queue (CQ) Creation (Send CQ & Recv CQ)
    uint32_t sendCqId = 0;
    uint32_t recvCqId = 0;
    NTSTATUS scqSt = rdma::RdmaCreateCompletionQueue(1024, &sendCqId);
    NTSTATUS rcqSt = rdma::RdmaCreateCompletionQueue(1024, &recvCqId);
    TEST_ASSERT(scqSt == STATUS_SUCCESS, "Creating Send CQ must succeed");
    TEST_ASSERT(rcqSt == STATUS_SUCCESS, "Creating Recv CQ must succeed");
    TEST_ASSERT(sendCqId > 0 && recvCqId > 0, "Valid CQ IDs must be allocated");

    // Stage 5: Reliable Connected Queue Pair (QP) Allocation
    uint32_t qpId = 0;
    NTSTATUS qpSt = rdma::RdmaCreateQueuePair(pdId, static_cast<uint32_t>(rdma::QueuePairType::ReliableConnected),
                                             sendCqId, recvCqId, 512, 512, &qpId);
    TEST_ASSERT(qpSt == STATUS_SUCCESS, "RdmaCreateQueuePair must succeed");
    TEST_ASSERT(qpId >= 401, "Allocated Queue Pair ID must be valid");
    const auto* qp = rdmaSub.getQueuePair(qpId);
    TEST_ASSERT(qp != nullptr, "Retrieved Queue Pair pointer must not be null");
    TEST_ASSERT(qp->state == rdma::QueuePairState::Init, "New QP must start in Init state");

    // Stage 6: Queue Pair State Machine Transition to RTS (Ready to Send)
    bool modOk = rdmaSub.modifyQueuePair(qpId, rdma::QueuePairState::RTS, 5001, "192.168.10.88", rdma::ROCE_V2_UDP_PORT, 0x400000);
    TEST_ASSERT(modOk, "Modifying Queue Pair state must succeed");
    qp = rdmaSub.getQueuePair(qpId);
    TEST_ASSERT(qp->state == rdma::QueuePairState::RTS, "QP state must now be RTS");
    TEST_ASSERT(qp->remoteQpId == 5001, "Remote QP ID must match");
    TEST_ASSERT(qp->remotePort == rdma::ROCE_V2_UDP_PORT, "Remote port must match RoCE v2 UDP port (4791)");

    // Stage 7: Zero-Copy Memory Region (MR) Registration
    uint32_t mrId = 0;
    uint32_t lkey = 0;
    uint32_t rkey = 0;
    NTSTATUS mrSt = rdma::RdmaRegisterMemoryRegion(pdId, 0x600010000000ULL, 16ULL * 1024ULL * 1024ULL,
                                                  rdma::RDMA_ACCESS_LOCAL_READ | rdma::RDMA_ACCESS_LOCAL_WRITE |
                                                  rdma::RDMA_ACCESS_REMOTE_READ | rdma::RDMA_ACCESS_REMOTE_WRITE,
                                                  &mrId, &lkey, &rkey);
    TEST_ASSERT(mrSt == STATUS_SUCCESS, "RdmaRegisterMemoryRegion must succeed");
    TEST_ASSERT(mrId >= 201, "Allocated MR ID must be valid");
    TEST_ASSERT(lkey != 0 && rkey != 0, "Valid lkey and rkey must be generated");

    // Stage 8: Post Receive Work Request Submission
    NTSTATUS recvSt = rdma::RdmaPostReceive(qpId, 1001, 4096);
    TEST_ASSERT(recvSt == STATUS_SUCCESS, "RdmaPostReceive must succeed on RTS/RTR queue pair");

    // Stage 9: Remote Direct Memory Access Write (RDMA Write) Execution
    uint32_t writeLatNs = 0;
    NTSTATUS writeSt = rdma::RdmaPostSend(qpId, 2001, static_cast<uint32_t>(rdma::RdmaWorkOp::RdmaWrite),
                                         65536, 0x600010000000ULL, rkey, &writeLatNs);
    TEST_ASSERT(writeSt == STATUS_SUCCESS, "RdmaPostSend with RdmaWrite must succeed");
    TEST_ASSERT(writeLatNs < 3000, "RDMA write latency must be sub-3.0 microseconds (< 3000 ns)");

    // Stage 10: Remote Direct Memory Access Read (RDMA Read) Execution
    uint32_t readLatNs = 0;
    NTSTATUS readSt = rdma::RdmaPostSend(qpId, 2002, static_cast<uint32_t>(rdma::RdmaWorkOp::RdmaRead),
                                        65536, 0x600010000000ULL, rkey, &readLatNs);
    TEST_ASSERT(readSt == STATUS_SUCCESS, "RdmaPostSend with RdmaRead must succeed");
    TEST_ASSERT(readLatNs < 3500, "RDMA read latency must be sub-3.5 microseconds (< 3500 ns)");

    // Stage 11: Hardware Completion Queue (CQ) Polling
    rdma::RdmaWorkCompletion completions[8]{};
    uint32_t completedCount = 0;
    NTSTATUS pollSt = rdma::RdmaPollCq(sendCqId, 8, completions, &completedCount);
    TEST_ASSERT(pollSt == STATUS_SUCCESS, "RdmaPollCq must succeed");
    TEST_ASSERT(completedCount == 2, "Must retrieve exactly 2 completed operations (Write and Read)");
    TEST_ASSERT(completions[0].status == rdma::RdmaCompletionStatus::Success, "Completion 1 status must be Success");
    TEST_ASSERT(completions[1].status == rdma::RdmaCompletionStatus::Success, "Completion 2 status must be Success");

    // Stage 12: SMB Direct Storage Acceleration Session Connection
    uint32_t smbSessId = 0;
    uint32_t smbQp = 0;
    NTSTATUS smbConnSt = rdma::SmbDirectConnect("\\\\TitanStorageCluster\\FastVHDX", &smbSessId, &smbQp);
    TEST_ASSERT(smbConnSt == STATUS_SUCCESS, "SmbDirectConnect must succeed");
    TEST_ASSERT(smbSessId >= 501, "Allocated SMB Direct session ID must be valid");
    const auto* smbSess = rdmaSub.getSmbSession(smbSessId);
    TEST_ASSERT(smbSess != nullptr && smbSess->isConnected, "SMB Direct session must be active and connected");
    TEST_ASSERT(smbSess->sendCreditsAvailable > 0, "SMB Direct send credits must be granted");

    // Stage 13: SMB Direct Remote High-Speed Write & Read Operations
    uint32_t smbWriteLat = 0;
    NTSTATUS smbWSt = rdma::SmbDirectRemoteWrite(smbSessId, 0, 1048576, &smbWriteLat);
    TEST_ASSERT(smbWSt == STATUS_SUCCESS, "SmbDirectRemoteWrite of 1MB segment must succeed");
    TEST_ASSERT(smbWriteLat < 3000, "SMB Direct write latency must be sub-3.0 microseconds");

    uint32_t smbReadLat = 0;
    NTSTATUS smbRSt = rdma::SmbDirectRemoteRead(smbSessId, 0, 1048576, &smbReadLat);
    TEST_ASSERT(smbRSt == STATUS_SUCCESS, "SmbDirectRemoteRead of 1MB segment must succeed");
    TEST_ASSERT(smbReadLat < 3500, "SMB Direct read latency must be sub-3.5 microseconds");

    // Stage 14: Wire-Speed Telemetry & Resilient Lossless Recovery
    rdma::RdmaTelemetry telem{};
    NTSTATUS telemSt = rdma::RdmaGetTelemetry(&telem);
    TEST_ASSERT(telemSt == STATUS_SUCCESS, "RdmaGetTelemetry must succeed");
    TEST_ASSERT(telem.sustainedBandwidthMBps > 10000, "Sustained line bandwidth must exceed 10,000 MB/s (> 80 Gbps)");
    TEST_ASSERT(telem.losslessFabricActive, "TitanRoCE autonomous lossless fabric recovery must be active");
    TEST_ASSERT(telem.pfcEnabled, "Priority Flow Control (PFC) must be enabled");
    TEST_ASSERT(telem.ecnEnabled, "Explicit Congestion Notification (ECN) must be enabled");

    // Stage 15: Driver C ABI Exports Verification (ndisrdma.sys & smbdirect.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaInitialize") != nullptr, "RdmaInitialize export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaGetVersion") != nullptr, "RdmaGetVersion export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaCreateProtectionDomain") != nullptr, "RdmaCreateProtectionDomain export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaCreateCompletionQueue") != nullptr, "RdmaCreateCompletionQueue export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaCreateQueuePair") != nullptr, "RdmaCreateQueuePair export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaRegisterMemoryRegion") != nullptr, "RdmaRegisterMemoryRegion export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaPostSend") != nullptr, "RdmaPostSend export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaPostReceive") != nullptr, "RdmaPostReceive export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaPollCq") != nullptr, "RdmaPollCq export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaGetTelemetry") != nullptr, "RdmaGetTelemetry export must exist");
    TEST_ASSERT(ldr.getExport("smbdirect.sys", "SmbDirectInitialize") != nullptr, "SmbDirectInitialize export must exist");
    TEST_ASSERT(ldr.getExport("smbdirect.sys", "SmbDirectConnect") != nullptr, "SmbDirectConnect export must exist");
    TEST_ASSERT(ldr.getExport("smbdirect.sys", "SmbDirectDisconnect") != nullptr, "SmbDirectDisconnect export must exist");
    TEST_ASSERT(ldr.getExport("smbdirect.sys", "SmbDirectRemoteWrite") != nullptr, "SmbDirectRemoteWrite export must exist");
    TEST_ASSERT(ldr.getExport("smbdirect.sys", "SmbDirectRemoteRead") != nullptr, "SmbDirectRemoteRead export must exist");

    // Stage 16: SCM Driver Service & Version Database Registration
    auto rdmaSvc = scm::ServiceControlManager::get().getServiceRecord(L"ndisrdma");
    TEST_ASSERT(rdmaSvc != nullptr, "ndisrdma service record must exist in SCM");
    TEST_ASSERT(rdmaSvc->startType == scm::SERVICE_BOOT_START, "ndisrdma must have SERVICE_BOOT_START");

    auto smbdSvc = scm::ServiceControlManager::get().getServiceRecord(L"smbdirect");
    TEST_ASSERT(smbdSvc != nullptr, "smbdirect service record must exist in SCM");
    TEST_ASSERT(smbdSvc->startType == scm::SERVICE_SYSTEM_START, "smbdirect must have SERVICE_SYSTEM_START");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("ndisrdma.sys") != nullptr, "ndisrdma.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("smbdirect.sys") != nullptr, "smbdirect.sys must be registered in Version Database");

    // Cleanup resources
    rdmaSub.smbDirectDisconnect(smbSessId);
    rdmaSub.deregisterMemoryRegion(mrId);
    rdmaSub.destroyQueuePair(qpId);
    rdmaSub.destroyCompletionQueue(sendCqId);
    rdmaSub.destroyCompletionQueue(recvCqId);
    rdmaSub.destroyProtectionDomain(pdId);

    std::cout << "[TEST] Suite 166: Remote Direct Memory Access (RDMA / RoCE v2 & InfiniBand) & SMB Direct Subsystem PASSED.\n";
}

void Test_PCIeSRIOV_PASID_SharedVirtualAddressing_Subsystem() {
    std::cout << "[TEST] Starting Suite 174: PCIe SR-IOV, PASID & Shared Virtual Addressing (SVA) Subsystem...\n";

    auto& sriovSub = micant::sriov::TitanSriovSubsystem::Instance();

    // Stage 1: Hardware Capabilities & Subsystem Initialization
    bool initOk = sriovSub.initialize();
    TEST_ASSERT(initOk, "TitanSriovSubsystem initialization must succeed");
    TEST_ASSERT(sriovSub.isInitialized(), "Subsystem must report initialized state");

    // Stage 2: Physical Function Registration & SR-IOV Extended Capability Discovery
    micant::sriov::SriovBdf nicBdf(1, 0, 0); // 01:00.0 (Intel E810 100GbE NIC)
    int32_t regStat = sriovSub.registerPhysicalFunction(
        nicBdf, 0x8086, 0x1592, "Intel E810-C 100GbE QSFP28 (TitanNIC)",
        8, 1, 1, 0x1889, 0x10000 // 8 Total VFs, VF Offset 1, VF Stride 1, VF DevID 0x1889, 64KB BAR0
    );
    TEST_ASSERT(regStat == micant::sriov::STATUS_SUCCESS, "registerPhysicalFunction for E810 must succeed");
    const auto& pfs = sriovSub.getPhysicalFunctions();
    TEST_ASSERT(pfs.find(nicBdf.toRaw()) != pfs.end(), "PF 01:00.0 must be registered");
    const auto& nicPf = pfs.at(nicBdf.toRaw());
    TEST_ASSERT(nicPf.sriovCap.capId == micant::sriov::PCI_EXT_CAP_ID_SRIOV, "CapId must be SR-IOV (0x0010)");
    TEST_ASSERT(nicPf.sriovCap.totalVFs == 8, "TotalVFs must be 8");
    TEST_ASSERT(nicPf.sriovCap.numVFs == 0, "Initial numVFs must be 0");

    // Stage 3: Virtual Function BDF Calculation & Offset/Stride Validation
    micant::sriov::SriovBdf gpuBdf(3, 0, 0); // 03:00.0 (NVIDIA H100 Tensor Core GPU)
    int32_t gpuRegStat = sriovSub.registerPhysicalFunction(
        gpuBdf, 0x10DE, 0x2330, "NVIDIA H100 SXM5 80GB (TitanGPU)",
        7, 1, 1, 0x2331, 0x40000 // 7 Total VFs (MIG partitions), 256KB BAR0
    );
    TEST_ASSERT(gpuRegStat == micant::sriov::STATUS_SUCCESS, "registerPhysicalFunction for H100 must succeed");

    // Stage 4: Dynamic Virtual Function Enablement (SR-IOV Control VF Enable)
    int32_t enStat = sriovSub.enableVirtualFunctions(nicBdf, 4);
    TEST_ASSERT(enStat == micant::sriov::STATUS_SUCCESS, "Enabling 4 VFs on E810 must succeed");
    const auto& updatedNicPf = sriovSub.getPhysicalFunctions().at(nicBdf.toRaw());
    TEST_ASSERT(updatedNicPf.sriovCap.numVFs == 4, "Configured numVFs must be 4");
    TEST_ASSERT((updatedNicPf.sriovCap.sriovControl & micant::sriov::SRIOV_CTRL_VF_ENABLE) != 0, "VF_ENABLE control bit must be set");
    TEST_ASSERT(updatedNicPf.virtualFunctions.size() == 4, "PF must hold 4 Virtual Function descriptors");

    // Verify VF BDF addresses
    TEST_ASSERT(updatedNicPf.virtualFunctions[0].bdf.bus == 1 && updatedNicPf.virtualFunctions[0].bdf.function == 1, "VF0 BDF must be 01:00.1");
    TEST_ASSERT(updatedNicPf.virtualFunctions[3].bdf.bus == 1 && updatedNicPf.virtualFunctions[3].bdf.function == 4, "VF3 BDF must be 01:00.4");

    // Stage 5: Out of Range / Exceeding TotalVFs Validation
    int32_t oobStat = sriovSub.enableVirtualFunctions(nicBdf, 16); // TotalVFs is 8
    TEST_ASSERT(oobStat == micant::sriov::STATUS_INVALID_PARAMETER, "Enabling VFs > TotalVFs must fail with STATUS_INVALID_PARAMETER");
    int32_t zeroVfStat = sriovSub.enableVirtualFunctions(nicBdf, 0);
    TEST_ASSERT(zeroVfStat == micant::sriov::STATUS_INVALID_PARAMETER, "Enabling 0 VFs must fail with STATUS_INVALID_PARAMETER");

    // Stage 6: VF Base Address Register (BAR) Partitioning & Sizing
    const auto& vf0 = updatedNicPf.virtualFunctions[0];
    const auto& vf1 = updatedNicPf.virtualFunctions[1];
    TEST_ASSERT(vf0.barAddress[0] == 0xE0000000, "VF0 BAR0 must start at 0xE0000000");
    TEST_ASSERT(vf0.barSize[0] == 0x10000, "VF0 BAR0 size must be 64KB");
    TEST_ASSERT(vf1.barAddress[0] == 0xE0010000, "VF1 BAR0 must start at 0xE0010000");
    TEST_ASSERT(vf1.barSize[0] == 0x10000, "VF1 BAR0 size must be 64KB");

    // Stage 7: Virtual Function Domain Assignment & Function Level Reset (FLR)
    micant::sriov::SriovBdf vf0Bdf = vf0.bdf;
    int32_t assignStat = sriovSub.assignVirtualFunction(vf0Bdf, "Hyper-V Tenant VM-01");
    TEST_ASSERT(assignStat == micant::sriov::STATUS_SUCCESS, "assignVirtualFunction must succeed");
    int32_t resetStat = sriovSub.resetVirtualFunction(vf0Bdf);
    TEST_ASSERT(resetStat == micant::sriov::STATUS_SUCCESS, "Function Level Reset (FLR) on VF0 must succeed");

    // Stage 8: PASID Extended Capability Inspection & Width Validation
    const auto& gpuPf = sriovSub.getPhysicalFunctions().at(gpuBdf.toRaw());
    TEST_ASSERT(gpuPf.pasidCap.capId == micant::sriov::PCI_EXT_CAP_ID_PASID, "PASID Extended Cap ID must match 0x001B");
    TEST_ASSERT(gpuPf.pasidCap.maxPasidWidth == 20, "PASID width must support 20 bits (1,048,576 address spaces)");
    TEST_ASSERT((gpuPf.pasidCap.pasidControl & micant::sriov::PASID_CTRL_ENABLE) != 0, "PASID_CTRL_ENABLE must be active");

    // Stage 9: Process Address Space ID (PASID) Binding (Shared Virtual Addressing / SVA)
    uint32_t testPasid = 42;
    uint32_t testPid = 4096;
    uint64_t cr3Base = 0x2B4000000ULL;
    int32_t bindStat = sriovSub.bindPasid(testPasid, testPid, "pytorch_worker.exe", cr3Base, gpuBdf, true, false);
    TEST_ASSERT(bindStat == micant::sriov::STATUS_SUCCESS, "bindPasid on GPU must succeed");
    const auto& bindings = sriovSub.getPasidBindings();
    auto bindKey = std::make_pair(gpuBdf.toRaw(), testPasid);
    TEST_ASSERT(bindings.find(bindKey) != bindings.end(), "PASID binding must exist in lookup table");
    const auto& bindInfo = bindings.at(bindKey);
    TEST_ASSERT(bindInfo.processId == testPid, "Bound PID must match 4096");
    TEST_ASSERT(bindInfo.cr3DirectoryBase == cr3Base, "CR3 must match 0x2B4000000");

    // Stage 10: PASID Range Checking & Duplicate Rejection
    int32_t dupStat = sriovSub.bindPasid(testPasid, 8192, "other.exe", cr3Base, gpuBdf);
    TEST_ASSERT(dupStat == micant::sriov::STATUS_INVALID_PARAMETER, "Duplicate PASID binding must return STATUS_INVALID_PARAMETER");
    int32_t oobPasidStat = sriovSub.bindPasid(0x00200000, 100, "oob.exe", cr3Base, gpuBdf); // Exceeds 20-bit PASID (0xFFFFF)
    TEST_ASSERT(oobPasidStat == micant::sriov::STATUS_INVALID_PARAMETER, "PASID > 20 bits must fail with STATUS_INVALID_PARAMETER");

    // Stage 11: Address Translation Services (ATS) - IOMMU Translation & Cache Hit
    uint64_t testVa = 0x7FFF00001000ULL; // Pre-mapped page in initialize()
    uint64_t physAddr = 0;
    uint32_t atsLatency = 0;
    // First translation: ATC Miss -> IOMMU page table walk (~45 ns)
    int32_t transStat1 = sriovSub.translateAddress(gpuBdf, testPasid, testVa + 0x120, false, &physAddr, &atsLatency);
    TEST_ASSERT(transStat1 == micant::sriov::STATUS_SUCCESS, "ATS translation 1 must succeed");
    TEST_ASSERT(physAddr == 0x100001120ULL, "Physical address must match 0x100001120");
    TEST_ASSERT(atsLatency == 45, "First access latency must be 45 ns (IOMMU walk)");

    // Second translation: ATC Hit (~4 ns)
    uint64_t cachedPa = 0;
    uint32_t cachedLat = 0;
    int32_t transStat2 = sriovSub.translateAddress(gpuBdf, testPasid, testVa + 0x200, false, &cachedPa, &cachedLat);
    TEST_ASSERT(transStat2 == micant::sriov::STATUS_SUCCESS, "ATS translation 2 must succeed");
    TEST_ASSERT(cachedPa == 0x100001200ULL, "Physical address must match 0x100001200");
    TEST_ASSERT(cachedLat == 4, "Subsequent access must hit ATC cache with 4 ns latency");

    // Stage 12: ATS Address Translation Cache (ATC) Invalidation
    int32_t invStat = sriovSub.invalidateAtsCache(gpuBdf, testPasid, testVa, 4096);
    TEST_ASSERT(invStat == micant::sriov::STATUS_SUCCESS, "invalidateAtsCache must succeed");
    // After invalidation, next translation must be a miss (45 ns)
    uint64_t postInvPa = 0;
    uint32_t postInvLat = 0;
    sriovSub.translateAddress(gpuBdf, testPasid, testVa + 0x120, false, &postInvPa, &postInvLat);
    TEST_ASSERT(postInvLat == 45, "Access after ATC invalidation must incur IOMMU walk (45 ns)");

    // Stage 13: Page Request Interface (PRI / PPR) - Peripheral Page Fault Handling
    uint64_t unmappedVa = 0x7FFF00088000ULL; // Not pre-mapped!
    uint64_t faultPa = 0;
    int32_t faultStat = sriovSub.translateAddress(gpuBdf, testPasid, unmappedVa, false, &faultPa, nullptr);
    TEST_ASSERT(faultStat == micant::sriov::STATUS_PAGE_FAULT, "Translating unmapped VA must yield STATUS_PAGE_FAULT");

    // Device issues Peripheral Page Request (PPR) over PCIe PRI
    micant::sriov::PageRequestPacket priReq{};
    priReq.prgIndex = 10;
    priReq.pasid = testPasid;
    priReq.virtualAddress = unmappedVa;
    priReq.readRequested = true;
    priReq.writeRequested = true;

    micant::sriov::PageResponsePacket priResp{};
    int32_t priStat = sriovSub.handlePageRequest(gpuBdf, priReq, &priResp);
    TEST_ASSERT(priStat == micant::sriov::STATUS_SUCCESS, "handlePageRequest must succeed");
    TEST_ASSERT(priResp.prgIndex == 10, "Response PRG Index must match request (10)");
    TEST_ASSERT(priResp.pasid == testPasid, "Response PASID must match request");
    TEST_ASSERT(priResp.responseCode == micant::sriov::PRG_RESPONSE_SUCCESS, "PRI response code must be SUCCESS (0)");
    TEST_ASSERT(priResp.latencyNs == 350, "PRI OS page-in latency must be 350 ns");

    // Stage 14: Translation Success Post-PRI Resolution
    uint64_t resolvedPa = 0;
    int32_t postPriStat = sriovSub.translateAddress(gpuBdf, testPasid, unmappedVa, false, &resolvedPa, nullptr);
    TEST_ASSERT(postPriStat == micant::sriov::STATUS_SUCCESS, "Translation after PRI demand page-in must succeed");
    TEST_ASSERT(resolvedPa >= 0x200000000ULL, "Resolved physical address must be in demand-paged range >= 0x200000000");

    // Stage 15: Monotonic Telemetry Verification
    const auto& telem = sriovSub.getTelemetry();
    TEST_ASSERT(telem.totalPfRegistered >= 2, "totalPfRegistered must be >= 2");
    TEST_ASSERT(telem.totalVfsEnabled >= 4, "totalVfsEnabled must be >= 4");
    TEST_ASSERT(telem.totalVfResets >= 1, "totalVfResets must be >= 1");
    TEST_ASSERT(telem.totalPasidBindings >= 1, "totalPasidBindings must be >= 1");
    TEST_ASSERT(telem.totalAtsTranslations >= 4, "totalAtsTranslations must be >= 4");
    TEST_ASSERT(telem.totalAtsHits >= 1, "totalAtsHits must be >= 1");
    TEST_ASSERT(telem.totalAtsMisses >= 3, "totalAtsMisses must be >= 3");
    TEST_ASSERT(telem.totalPriPageFaults >= 1, "totalPriPageFaults must be >= 1");
    TEST_ASSERT(telem.totalPriResponsesSent >= 1, "totalPriResponsesSent must be >= 1");

    // Stage 16: SCM Boot Driver Registration & Version Database Audit
    auto& scm = micant::scm::ServiceControlManager::get();
    auto sriovSvc = scm.getServiceRecord(L"pci_sriov");
    TEST_ASSERT(sriovSvc != nullptr, "pci_sriov.sys must be registered in SCM");
    TEST_ASSERT(sriovSvc->startType == micant::scm::SERVICE_BOOT_START, "pci_sriov must be Boot start");

    auto svaSvc = scm.getServiceRecord(L"pcie_sva");
    TEST_ASSERT(svaSvc != nullptr, "pcie_sva.sys must be registered in SCM");
    TEST_ASSERT(svaSvc->startType == micant::scm::SERVICE_SYSTEM_START, "pcie_sva must be System start");

    const auto* modSriov = micant::version::VersionDatabase::Instance().GetModuleInfo("pci_sriov.sys");
    TEST_ASSERT(modSriov != nullptr, "pci_sriov.sys must be registered in VersionDatabase");
    TEST_ASSERT(modSriov->stringTable.at("ProductVersion") == "10.0.26100.1", "pci_sriov.sys version must match 10.0.26100.1");

    // C ABI Driver Exports
    uint32_t cMajor = 0, cMinor = 0, cBuild = 0;
    int32_t vStat = micant::sriov::SriovGetVersion(&cMajor, &cMinor, &cBuild);
    TEST_ASSERT(vStat == micant::sriov::STATUS_SUCCESS, "SriovGetVersion must succeed");
    TEST_ASSERT(cMajor == 10 && cBuild == 26100, "SR-IOV version must match 10.0.26100");

    // C ABI SRIOV enable/disable test
    int32_t cAbiEnStat = micant::sriov::SriovEnableVirtualFunctions(1, 0, 0, 2);
    TEST_ASSERT(cAbiEnStat == micant::sriov::STATUS_SUCCESS, "SriovEnableVirtualFunctions C ABI must succeed");
    int32_t cAbiDisStat = micant::sriov::SriovDisableVirtualFunctions(1, 0, 0);
    TEST_ASSERT(cAbiDisStat == micant::sriov::STATUS_SUCCESS, "SriovDisableVirtualFunctions C ABI must succeed");

    std::cout << "[TEST] Suite 174: PCIe SR-IOV, PASID & Shared Virtual Addressing Subsystem PASSED.\n";
}

void Test_ConfidentialComputing_TEE_Subsystem() {
    std::cout << "[TEST] Starting Suite 171: Intel SGX / TDX & AMD SEV-SNP Confidential Computing Subsystem...\n";

    // Stage 1: Subsystem Initialization & Singleton Verification
    auto& teeSub = micant::tee::TitanTeeSubsystem::Instance();
    bool initOk = teeSub.initialize();
    TEST_ASSERT(initOk, "TitanTEE Subsystem must initialize successfully");
    TEST_ASSERT(teeSub.isInitialized(), "TitanTEE Subsystem must report initialized state");

    // Stage 2: Hardware Capabilities & Memory Encryption Engine
    const auto& caps = teeSub.getCapabilities();
    TEST_ASSERT(caps.supportsIntelSgx, "Hardware must support Intel SGX 1");
    TEST_ASSERT(caps.supportsIntelSgx2, "Hardware must support Intel SGX 2 dynamic EPC");
    TEST_ASSERT(caps.supportsIntelTdx, "Hardware must support Intel TDX 1.5 Trust Domains");
    TEST_ASSERT(caps.supportsAmdSevSnp, "Hardware must support AMD SEV-SNP Secure Nested Paging");
    TEST_ASSERT(caps.supportsWindowsVbs, "Hardware must support Windows VBS Enclaves");
    TEST_ASSERT(caps.epcTotalSizeBytes == 512ULL * 1024 * 1024, "EPC memory aperture must be 512 MB");
    TEST_ASSERT(caps.hardwareEncryptionAlgo.find("AES-256-XTS") != std::string::npos, "MEE must use AES-256-XTS");

    // Stage 3: Dynamic Enclave Creation (Intel SGX 2)
    uint32_t encSgx = teeSub.createEnclave("SecureVault_SGX", micant::tee::TeeTechnology::IntelSGX,
                                           micant::tee::TeeEnclaveType::Dynamic_SGX2, 64 * 1024, 1, 1);
    TEST_ASSERT(encSgx > 0, "Intel SGX 2 enclave creation must return valid non-zero ID");

    // Stage 4: EPC Memory Allocation & Telemetry Tracking
    micant::tee::TeeEnclaveDescriptor descSgx{};
    bool getDescOk = teeSub.getEnclaveDescriptor(encSgx, &descSgx);
    TEST_ASSERT(getDescOk, "Enclave descriptor query must succeed");
    TEST_ASSERT(descSgx.epcPagesAllocated == 16, "64KB enclave must allocate exactly 16 4KB EPC pages");
    TEST_ASSERT(descSgx.state == micant::tee::TeeEnclaveState::Created, "Enclave state must be Created");
    TEST_ASSERT(descSgx.baseAddress != 0, "Enclave must have non-zero base address");

    const auto& telem = teeSub.getTelemetry();
    TEST_ASSERT(telem.activeEnclaves >= 1, "Active enclaves count must be >= 1");
    TEST_ASSERT(telem.freeEpcPages == telem.totalEpcPages - 16, "Free EPC pages must reflect allocation");

    // Stage 5: Enclave Code/Data Loading & EEXTEND Measurement
    std::vector<uint8_t> enclaveCode(4096, 0x90);
    enclaveCode[0] = 0x48; enclaveCode[1] = 0x31; enclaveCode[2] = 0xC0; // xor rax, rax
    enclaveCode[3] = 0xC3; // ret
    auto initialMr = descSgx.mrEnclave;
    bool loadOk = teeSub.loadEnclaveData(encSgx, 0x1000, enclaveCode.data(),
                                        static_cast<uint32_t>(enclaveCode.size()),
                                        micant::tee::TeePagePermissions::Read | micant::tee::TeePagePermissions::Execute);
    TEST_ASSERT(loadOk, "Loading code page into enclave must succeed");
    teeSub.getEnclaveDescriptor(encSgx, &descSgx);
    TEST_ASSERT(descSgx.mrEnclave != initialMr, "EEXTEND must update MRENCLAVE cryptographic hash");

    // Stage 6: Enclave Finalization & EINIT
    uint8_t authorKey[32]{};
    std::fill(std::begin(authorKey), std::end(authorKey), 0x7E);
    bool initEncOk = teeSub.initializeEnclave(encSgx, authorKey, sizeof(authorKey));
    TEST_ASSERT(initEncOk, "Enclave initialization (EINIT) must succeed");
    teeSub.getEnclaveDescriptor(encSgx, &descSgx);
    TEST_ASSERT(descSgx.state == micant::tee::TeeEnclaveState::Initialized, "Enclave state must transition to Initialized");
    TEST_ASSERT(descSgx.mrSigner[0] == 0x7E, "MRSIGNER must reflect author key");

    // Stage 7: Hardware-Encrypted Execution & Low-Latency Transition (EENTER / EEXIT)
    uint64_t inputVal = 0x1122334455667788ULL;
    uint64_t outputVal = 0;
    uint32_t latencyNs = 0;
    bool enterOk = teeSub.enterEnclave(encSgx, inputVal, &outputVal, &latencyNs);
    TEST_ASSERT(enterOk, "Hardware enclave entry and execution must succeed");
    TEST_ASSERT(outputVal != 0, "Enclave output value must be non-zero computed result");
    TEST_ASSERT(latencyNs < 100, "Hardware transition latency must be sub-100 nanoseconds");

    // Stage 8: Asynchronous Enclave Exit (AEX) Intercept Handling
    bool aexOk = teeSub.simulateAex(encSgx);
    TEST_ASSERT(aexOk, "Simulating Asynchronous Enclave Exit (AEX) must succeed");
    teeSub.getEnclaveDescriptor(encSgx, &descSgx);
    TEST_ASSERT(descSgx.state == micant::tee::TeeEnclaveState::Exited, "Enclave state must be Exited after AEX");
    TEST_ASSERT(descSgx.aexCount == 1, "Enclave AEX counter must increment to 1");

    // Stage 9: Enclave Resume (ERESUME)
    bool resumeOk = teeSub.resumeEnclave(encSgx);
    TEST_ASSERT(resumeOk, "Resuming enclave (ERESUME) must succeed");
    teeSub.getEnclaveDescriptor(encSgx, &descSgx);
    TEST_ASSERT(descSgx.state == micant::tee::TeeEnclaveState::Initialized, "Enclave state must return to Initialized");

    // Stage 10: Intel TDX Trust Domain Provisioning
    uint32_t encTdx = teeSub.createEnclave("TrustDomain_TDX_Guest", micant::tee::TeeTechnology::IntelTDX,
                                           micant::tee::TeeEnclaveType::TrustDomain_TDX, 128 * 1024, 2, 1);
    TEST_ASSERT(encTdx > 0, "Intel TDX Trust Domain creation must succeed");
    micant::tee::TeeEnclaveDescriptor descTdx{};
    teeSub.getEnclaveDescriptor(encTdx, &descTdx);
    TEST_ASSERT(descTdx.tech == micant::tee::TeeTechnology::IntelTDX, "Enclave tech must be Intel TDX");
    TEST_ASSERT(descTdx.epcPagesAllocated == 32, "128KB Trust Domain must allocate 32 EPC pages");
    teeSub.initializeEnclave(encTdx);

    // Stage 11: AMD SEV-SNP Confidential VM Creation
    uint32_t encSnp = teeSub.createEnclave("ConfidentialVM_SNP", micant::tee::TeeTechnology::AmdSevSnp,
                                           micant::tee::TeeEnclaveType::ConfidentialVM_SNP, 256 * 1024, 3, 2);
    TEST_ASSERT(encSnp > 0, "AMD SEV-SNP Confidential VM creation must succeed");
    micant::tee::TeeEnclaveDescriptor descSnp{};
    teeSub.getEnclaveDescriptor(encSnp, &descSnp);
    TEST_ASSERT(descSnp.tech == micant::tee::TeeTechnology::AmdSevSnp, "Enclave tech must be AMD SEV-SNP");
    TEST_ASSERT(descSnp.epcPagesAllocated == 64, "256KB Confidential VM must allocate 64 EPC pages");
    teeSub.initializeEnclave(encSnp);

    // Stage 12: Cryptographic Attestation Quote Generation
    std::string appNonce = "MicaNT_Confidential_Attestation_Verification_Nonce_2026_Hex";
    micant::tee::TeeAttestationReport report{};
    bool quoteOk = teeSub.generateAttestationReport(encTdx,
        reinterpret_cast<const uint8_t*>(appNonce.data()),
        static_cast<uint32_t>(appNonce.size()), &report);
    TEST_ASSERT(quoteOk, "Generating cryptographic attestation quote must succeed");
    TEST_ASSERT(report.magic == 0x54454541, "Attestation report magic must match TEEA");
    TEST_ASSERT(report.tech == micant::tee::TeeTechnology::IntelTDX, "Report tech must match Trust Domain");
    TEST_ASSERT(report.valid == 1, "Report validity flag must be 1");

    // Stage 13: Cryptographic Attestation Verification
    bool quoteValid = false;
    bool verifyOk = teeSub.verifyAttestationReport(report, &quoteValid);
    TEST_ASSERT(verifyOk, "Attestation report verification call must succeed");
    TEST_ASSERT(quoteValid, "Valid report signature must verify successfully");

    // Stage 14: Tampered Quote Detection
    micant::tee::TeeAttestationReport badReport = report;
    badReport.signature[10] ^= 0xFF; // Corrupt signature byte
    bool badValid = true;
    teeSub.verifyAttestationReport(badReport, &badValid);
    TEST_ASSERT(!badValid, "Tampered signature must be rejected by verification engine");

    // Stage 15: Enclave Termination & Dynamic EPC Reclamation
    uint32_t freeBefore = teeSub.getTelemetry().freeEpcPages;
    bool termOk = teeSub.terminateEnclave(encSnp);
    TEST_ASSERT(termOk, "Terminating AMD SEV-SNP enclave must succeed");
    uint32_t freeAfter = teeSub.getTelemetry().freeEpcPages;
    TEST_ASSERT(freeAfter == freeBefore + 64, "Dynamic EPC memory must be reclaimed (+64 pages)");
    teeSub.getEnclaveDescriptor(encSnp, &descSnp);
    TEST_ASSERT(descSnp.state == micant::tee::TeeEnclaveState::Terminated, "Enclave state must be Terminated");

    // Stage 16: C ABI Driver Exports, SCM Service, and Version Database Registration
    uint32_t cMajor = 0, cMinor = 0, cBuild = 0;
    int32_t vStat = micant::tee::TeeGetVersion(&cMajor, &cMinor, &cBuild);
    TEST_ASSERT(vStat == micant::tee::STATUS_SUCCESS, "TeeGetVersion must succeed");
    TEST_ASSERT(cMajor == 10 && cBuild == 26100, "Tee version must be 10.0.26100");

    uint32_t cEncId = 0;
    int32_t cStat = micant::tee::TeeCreateEnclave("CabIEnclave",
        static_cast<uint32_t>(micant::tee::TeeTechnology::IntelSGX),
        static_cast<uint32_t>(micant::tee::TeeEnclaveType::Standard_SGX1), 32 * 1024, &cEncId);
    TEST_ASSERT(cStat == micant::tee::STATUS_SUCCESS, "TeeCreateEnclave C ABI must succeed");
    TEST_ASSERT(cEncId > 0, "C ABI must allocate valid enclave ID");

    auto& scm = micant::scm::ServiceControlManager::get();
    auto virtSvc = scm.getServiceRecord(L"virtenclave");
    TEST_ASSERT(virtSvc != nullptr, "virtenclave.sys must be registered in SCM");
    TEST_ASSERT(virtSvc->startType == micant::scm::SERVICE_BOOT_START, "virtenclave must be Boot start");

    const auto* modVirt = micant::version::VersionDatabase::Instance().GetModuleInfo("virtenclave.sys");
    TEST_ASSERT(modVirt != nullptr, "virtenclave.sys must be registered in VersionDatabase");
    TEST_ASSERT(modVirt->stringTable.at("ProductVersion") == "10.0.26100.1", "virtenclave.sys version must match 10.0.26100.1");

    std::cout << "[TEST] Suite 171: Intel SGX / TDX & AMD SEV-SNP Confidential Computing Subsystem PASSED.\n";
}

void Test_USBTypeC_UCSI_PowerDelivery31_Subsystem() {
    std::cout << "[TEST] Starting Suite 163: USB Type-C (UCSI 2.1/3.0) & USB PD 3.1 240W EPR Subsystem...\n";

    // Initialize Subsystem & Register Components
    ucsi::InitializeUcsiSubsystem();
    auto& ucsiSub = ucsi::TitanUcsiSubsystem::Instance();
    TEST_ASSERT(ucsiSub.isInitialized() == true, "TitanUCSI subsystem must be initialized");

    // Stage 1: UCSI Specification Version Verification (Revision 3.0)
    uint32_t maj = 0, min = 0;
    ucsiSub.getVersion(&maj, &min);
    TEST_ASSERT(maj == 3 && min == 0, "UCSI specification version must be 3.0");

    // Stage 2: Platform Policy Manager (PPM) & Physical Connector Enumeration
    uint8_t connCount = ucsiSub.getConnectorCount();
    TEST_ASSERT(connCount == 4, "Platform Policy Manager must report 4 physical Type-C connectors");

    // Stage 3: Connector 1 (Left Rear) Capabilities & 240W EPR Support
    const auto* cap1 = ucsiSub.getConnectorCapability(1);
    TEST_ASSERT(cap1 != nullptr, "Connector 1 capability lookup must succeed");
    TEST_ASSERT(cap1->supportsDfp == true, "Connector 1 must support DFP (Host)");
    TEST_ASSERT(cap1->supportsUfp == true, "Connector 1 must support UFP (Device)");
    TEST_ASSERT(cap1->supportsSource == true, "Connector 1 must support Power Source");
    TEST_ASSERT(cap1->supportsSink == true, "Connector 1 must support Power Sink");
    TEST_ASSERT(cap1->supportsEpr240W == true, "Connector 1 must support 240W Extended Power Range (EPR)");
    TEST_ASSERT(cap1->supportsDisplayPortAltMode == true, "Connector 1 must support DisplayPort Alt Mode");
    TEST_ASSERT(cap1->supportsThunderboltAltMode == true, "Connector 1 must support Thunderbolt / USB4 Alt Mode");

    // Stage 4: Connector 1 Sink PDOs (Inbound Power Capabilities)
    TEST_ASSERT(cap1->sinkCapabilities.size() >= 8, "Connector 1 must advertise at least 8 Sink PDOs");
    bool found48v = false;
    bool foundAvs = false;
    for (const auto& pdo : cap1->sinkCapabilities) {
        if (pdo.type == ucsi::UsbPdPdoType::FixedSupply && pdo.voltageMillivolts == 48000 && pdo.maxPowerMilliwatts == 240000) {
            found48v = true;
        }
        if (pdo.type == ucsi::UsbPdPdoType::AdjustableVoltageSupply && pdo.maxPowerMilliwatts == 240000) {
            foundAvs = true;
        }
    }
    TEST_ASSERT(found48v == true, "Connector 1 must support Fixed 48V @ 5A = 240W EPR Sink PDO");
    TEST_ASSERT(foundAvs == true, "Connector 1 must support AVS 15V-48V 240W EPR Sink PDO");

    // Stage 5: Connector 1 Active Power Contract & Status
    const auto* st1 = ucsiSub.getConnectorStatus(1);
    TEST_ASSERT(st1 != nullptr, "Connector 1 status lookup must succeed");
    TEST_ASSERT(st1->isConnected == true, "Connector 1 must be connected (240W GaN Adapter)");
    TEST_ASSERT(st1->powerRole == ucsi::UcsiPowerRole::Sink, "Connector 1 must be in Sink role (charging host)");
    TEST_ASSERT(st1->isPowerContractActive == true, "Connector 1 must have an active power contract");
    TEST_ASSERT(st1->currentPowerRange == ucsi::UsbPdPowerRange::ExtendedPowerRange_EPR, "Connector 1 power range must be EPR");
    TEST_ASSERT(st1->negotiatedVoltageMv == 48000, "Negotiated voltage must be 48V (48,000 mV)");
    TEST_ASSERT(st1->negotiatedCurrentMa == 5000, "Negotiated current must be 5A (5,000 mA)");
    TEST_ASSERT(st1->negotiatedPowerMw == 240000, "Negotiated power must be 240,000 mW (240W)");
    TEST_ASSERT(st1->batteryChargingState == 1, "Battery charging state must be Charging");

    // Stage 6: Connector 1 Cable E-Marker Discovery (SOP' Communication)
    const auto* cb1 = ucsiSub.getCableInfo(1);
    TEST_ASSERT(cb1 != nullptr, "Connector 1 cable info must exist");
    TEST_ASSERT(cb1->hasElectronicMarker == true, "Connector 1 cable must contain E-Marker chip");
    TEST_ASSERT(cb1->maxVoltageMillivolts >= 48000, "Cable must be rated for >= 48V");
    TEST_ASSERT(cb1->maxCurrentMilliamps == 5000, "Cable must be rated for 5A");
    TEST_ASSERT(cb1->isEprCapable == true, "Cable must be EPR capable (240W rated)");
    TEST_ASSERT(cb1->maxDataSpeedGbps >= 80, "Cable must support 80 Gbps PAM3 high-speed signaling");

    // Stage 7: Connector 2 DisplayPort 2.1 UHBR20 Alt-Mode & Concurrent 65W PD Passthrough
    const auto* st2 = ucsiSub.getConnectorStatus(2);
    TEST_ASSERT(st2 != nullptr && st2->isConnected == true, "Connector 2 must be connected to external monitor");
    TEST_ASSERT(st2->activeAltMode == ucsi::UsbAltMode::DisplayPort21_UHBR20, "Connector 2 must be in DisplayPort 2.1 Alt Mode");
    TEST_ASSERT(st2->negotiatedPowerMw == 65000, "Connector 2 must negotiate 65W PD passthrough from monitor");

    // Stage 8: Connector 3 Peripheral Source Operation (15W External SSD)
    const auto* st3 = ucsiSub.getConnectorStatus(3);
    TEST_ASSERT(st3 != nullptr && st3->isConnected == true, "Connector 3 must be connected to external SSD");
    TEST_ASSERT(st3->powerRole == ucsi::UcsiPowerRole::Source, "Connector 3 must be in Source role (providing power)");
    TEST_ASSERT(st3->negotiatedPowerMw == 15000, "Connector 3 must deliver 15W (5V @ 3A)");
    const auto* cb3 = ucsiSub.getCableInfo(3);
    TEST_ASSERT(cb3 != nullptr && cb3->hasElectronicMarker == false, "Standard 15W cable does not require E-Marker");

    // Stage 9: Connector 4 Disconnected State & PPS Fast Charge Capability
    const auto* st4 = ucsiSub.getConnectorStatus(4);
    TEST_ASSERT(st4 != nullptr && st4->isConnected == false, "Connector 4 must report disconnected");
    const auto* cap4 = ucsiSub.getConnectorCapability(4);
    TEST_ASSERT(cap4 != nullptr, "Connector 4 capability must exist");
    bool foundPps = false;
    for (const auto& pdo : cap4->sourceCapabilities) {
        if (pdo.type == ucsi::UsbPdPdoType::ProgrammablePowerSupply) foundPps = true;
    }
    TEST_ASSERT(foundPps == true, "Connector 4 must support PPS (Programmable Power Supply)");

    // Stage 10: UCSI Mailbox Command Dispatcher: PPM_RESET (0x01)
    std::vector<uint8_t> resetOut;
    uint32_t cci = 0;
    NTSTATUS rSt = ucsiSub.executeUcsiCommand(ucsi::UcsiCommand::PpmReset, 0, {}, resetOut, &cci);
    TEST_ASSERT(rSt == STATUS_SUCCESS, "PPM_RESET command execution must succeed");
    TEST_ASSERT(cci & ucsi::UCSI_CCI_COMMAND_COMPLETED_INDICATOR, "CCI command completed indicator must be set");
    TEST_ASSERT(cci & ucsi::UCSI_CCI_RESET_COMPLETED_INDICATOR, "CCI reset completed indicator must be set");

    // Stage 11: UCSI Mailbox Command: GET_CAPABILITY (0x06)
    std::vector<uint8_t> capOut;
    NTSTATUS gSt = ucsiSub.executeUcsiCommand(ucsi::UcsiCommand::GetCapability, 0, {}, capOut, &cci);
    TEST_ASSERT(gSt == STATUS_SUCCESS, "GET_CAPABILITY command execution must succeed");
    TEST_ASSERT(capOut.size() >= 2 && capOut[0] == 4, "Capability payload must report 4 connectors");

    // Stage 12: Dynamic Role Swapping: Power Role Swap (PR_SWAP)
    auto prevPowerRole = st2->powerRole;
    bool swapPrOk = ucsiSub.executeRoleSwap(2, true, false);
    TEST_ASSERT(swapPrOk == true, "Power role swap on Connector 2 must succeed");
    TEST_ASSERT(st2->powerRole != prevPowerRole, "Power role must toggle following PR_SWAP");
    ucsiSub.executeRoleSwap(2, true, false); // Restore to original
    TEST_ASSERT(st2->powerRole == prevPowerRole, "Power role must restore to original");

    // Stage 13: Dynamic Role Swapping: Data Role Swap (DR_SWAP)
    auto prevDataRole = st2->dataRole;
    bool swapDrOk = ucsiSub.executeRoleSwap(2, false, true);
    TEST_ASSERT(swapDrOk == true, "Data role swap on Connector 2 must succeed");
    TEST_ASSERT(st2->dataRole != prevDataRole, "Data role must toggle following DR_SWAP");
    ucsiSub.executeRoleSwap(2, false, true); // Restore to original
    TEST_ASSERT(st2->dataRole == prevDataRole, "Data role must restore to original");

    // Stage 14: USB PD Power Contract Dynamic Renegotiation (140W EPR Contract)
    bool negoOk = ucsiSub.negotiatePowerContract(1, 28000, 5000); // 28V @ 5A = 140W
    TEST_ASSERT(negoOk == true, "Renegotiating power contract must succeed");
    TEST_ASSERT(st1->negotiatedVoltageMv == 28000, "Negotiated voltage must update to 28,000 mV");
    TEST_ASSERT(st1->negotiatedPowerMw == 140000, "Negotiated power must update to 140,000 mW (140W)");
    TEST_ASSERT(st1->currentPowerRange == ucsi::UsbPdPowerRange::ExtendedPowerRange_EPR, "140W contract must remain in EPR range");
    ucsiSub.negotiatePowerContract(1, 48000, 5000); // Restore to 240W

    // Stage 15: Dynamic Loader C ABI Driver Exports (ucsi.sys, usbc.sys, ppm.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("ucsi.sys", "UcsiInitialize") != nullptr, "ucsi.sys UcsiInitialize must exist");
    TEST_ASSERT(ldr.getExport("ucsi.sys", "UcsiGetVersion") != nullptr, "ucsi.sys UcsiGetVersion must exist");
    TEST_ASSERT(ldr.getExport("ucsi.sys", "UcsiGetConnectorCount") != nullptr, "ucsi.sys UcsiGetConnectorCount must exist");
    TEST_ASSERT(ldr.getExport("ucsi.sys", "UcsiGetConnectorStatus") != nullptr, "ucsi.sys UcsiGetConnectorStatus must exist");
    TEST_ASSERT(ldr.getExport("ucsi.sys", "UcsiGetConnectorCapability") != nullptr, "ucsi.sys UcsiGetConnectorCapability must exist");

    TEST_ASSERT(ldr.getExport("usbc.sys", "UsbcGetCableProperties") != nullptr, "usbc.sys UsbcGetCableProperties must exist");
    TEST_ASSERT(ldr.getExport("usbc.sys", "UsbcExecuteRoleSwap") != nullptr, "usbc.sys UsbcExecuteRoleSwap must exist");
    TEST_ASSERT(ldr.getExport("usbc.sys", "UsbcNegotiatePowerContract") != nullptr, "usbc.sys UsbcNegotiatePowerContract must exist");
    TEST_ASSERT(ldr.getExport("usbc.sys", "UsbcConfigureAlternateMode") != nullptr, "usbc.sys UsbcConfigureAlternateMode must exist");

    TEST_ASSERT(ldr.getExport("ppm.sys", "PpmSendCommand") != nullptr, "ppm.sys PpmSendCommand must exist");
    TEST_ASSERT(ldr.getExport("ppm.sys", "PpmGetTelemetry") != nullptr, "ppm.sys PpmGetTelemetry must exist");

    // Direct C ABI Calls Verification
    uint8_t abiConnCount = 0;
    NTSTATUS cSt = ucsi::UcsiGetConnectorCount(&abiConnCount);
    TEST_ASSERT(cSt == STATUS_SUCCESS && abiConnCount == 4, "UcsiGetConnectorCount C ABI call must succeed");

    ucsi::UcsiConnectorStatus abiStatus{};
    NTSTATUS sSt = ucsi::UcsiGetConnectorStatus(1, &abiStatus);
    TEST_ASSERT(sSt == STATUS_SUCCESS && abiStatus.isConnected == true, "UcsiGetConnectorStatus C ABI call must succeed");

    ucsi::UsbTypeCCableInfo abiCable{};
    NTSTATUS cbSt = ucsi::UsbcGetCableProperties(1, &abiCable);
    TEST_ASSERT(cbSt == STATUS_SUCCESS && abiCable.isEprCapable == true, "UsbcGetCableProperties C ABI call must succeed");

    // Stage 16: SCM Service Control Manager Records & Version Database Registrations
    auto ucsiSvc = scm::ServiceControlManager::get().getServiceRecord(L"ucsi");
    TEST_ASSERT(ucsiSvc != nullptr, "ucsi service record must exist in SCM");
    TEST_ASSERT(ucsiSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "ucsi must be a kernel driver");
    TEST_ASSERT(ucsiSvc->startType == scm::SERVICE_BOOT_START, "ucsi must have boot start type");

    auto usbcSvc = scm::ServiceControlManager::get().getServiceRecord(L"usbc");
    TEST_ASSERT(usbcSvc != nullptr, "usbc service record must exist in SCM");
    TEST_ASSERT(usbcSvc->startType == scm::SERVICE_BOOT_START, "usbc must have boot start type");

    auto ppmSvc = scm::ServiceControlManager::get().getServiceRecord(L"ppm");
    TEST_ASSERT(ppmSvc != nullptr, "ppm service record must exist in SCM");
    TEST_ASSERT(ppmSvc->startType == scm::SERVICE_BOOT_START, "ppm must have boot start type");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("ucsi.sys") != nullptr, "ucsi.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("usbc.sys") != nullptr, "usbc.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("ppm.sys") != nullptr, "ppm.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 163: USB Type-C (UCSI 2.1/3.0) & USB PD 3.1 240W EPR Subsystem PASSED.\n";
}

void Test_UniversalSerialBus_USB_xHCI_Subsystem() {
    using namespace micant::usb;

    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 151: Universal Serial Bus (USB 3.2 / xHCI) & Hub Subsystem      \n";
    std::cout << "========================================================================\n";

    // Stage 1: Subsystem Initialization & Host Controller Register Space
    InitializeUsbSubsystem();
    auto& sub = TitanUsbSubsystem::Instance();
    auto hc = sub.getPrimaryController();
    TEST_ASSERT(hc != nullptr, "Primary xHCI Host Controller must exist");
    TEST_ASSERT(hc->isRunning(), "xHCI Host Controller must be in RUNNING state (USBCMD.RS=1)");
    TEST_ASSERT(hc->getHciVersion() == 0x0120, "xHCI revision must be 1.2 (0x0120)");
    TEST_ASSERT(hc->getMaxSlots() == 32, "xHCI maximum slots must be 32");
    TEST_ASSERT(hc->getMaxPorts() == 8, "xHCI maximum root hub ports must be 8");

    // Stage 2: Root Hub Port Status & Default Device Attachments
    auto rh = hc->getRootHub();
    TEST_ASSERT(rh != nullptr, "Root Hub must exist");
    TEST_ASSERT(rh->getPortCount() == 8, "Root Hub port count must match 8");

    for (uint8_t p = 0; p < 8; ++p) {
        const auto& pStat = rh->getPortStatus(p);
        TEST_ASSERT(pStat.powered, "All root hub ports must be powered");
    }

    auto flashDev = rh->getAttachedDevice(0);
    auto mouseDev = rh->getAttachedDevice(1);
    auto serialDev = rh->getAttachedDevice(2);
    TEST_ASSERT(flashDev != nullptr, "Port 0 must have Mass Storage device attached");
    TEST_ASSERT(mouseDev != nullptr, "Port 1 must have HID Mouse device attached");
    TEST_ASSERT(serialDev != nullptr, "Port 2 must have CDC-ACM Serial device attached");

    // Stage 3: Standard Descriptor Verification & Parsing
    const auto& devDesc = flashDev->getDeviceDescriptor();
    TEST_ASSERT(devDesc.bLength == 18, "Device descriptor bLength must be 18");
    TEST_ASSERT(devDesc.bDescriptorType == DescriptorType::Device, "Descriptor type must be Device (0x01)");
    TEST_ASSERT(devDesc.bcdUSB == 0x0320, "bcdUSB must be 0x0320 for USB 3.2 SuperSpeed");
    TEST_ASSERT(devDesc.bDeviceClass == ClassCode::MassStorage, "Flash drive class must be Mass Storage (0x08)");
    TEST_ASSERT(devDesc.idVendor == 0x0781, "SanDisk VID must be 0x0781");
    TEST_ASSERT(devDesc.idProduct == 0x5583, "SanDisk Ultra PID must be 0x5583");

    // String Descriptors
    TEST_ASSERT(flashDev->getManufacturerString() == "SanDisk", "Manufacturer string must match");
    TEST_ASSERT(flashDev->getProductString() == "Ultra USB 3.0 Flash Drive", "Product string must match");
    TEST_ASSERT(!flashDev->getSerialNumber().empty(), "Serial number string must not be empty");

    // Stage 4: xHCI Command Ring & Event Ring Execution
    xhci::TRB enableCmd{};
    enableCmd.setType(xhci::TrbType::EnableSlotCmd);
    xhci::TRB compEvent{};
    bool cmdOk = hc->submitCommand(enableCmd, compEvent);
    TEST_ASSERT(cmdOk, "Submitting EnableSlotCmd to xHCI command ring must succeed");
    TEST_ASSERT(compEvent.getType() == xhci::TrbType::CommandCompletionEvent, "Must produce CommandCompletionEvent");
    TEST_ASSERT(compEvent.getCompletionCode() == xhci::CompCode::Success, "Completion code must be Success");
    uint8_t newSlot = compEvent.getSlotId();
    TEST_ASSERT(newSlot > 0, "Allocated slot ID must be non-zero");

    xhci::TRB addrCmd{};
    addrCmd.setType(xhci::TrbType::AddressDeviceCmd);
    addrCmd.setSlotId(flashDev->getSlotId());
    cmdOk = hc->submitCommand(addrCmd, compEvent);
    TEST_ASSERT(cmdOk && compEvent.getCompletionCode() == xhci::CompCode::Success, "AddressDeviceCmd must succeed");

    xhci::TRB cfgCmd{};
    cfgCmd.setType(xhci::TrbType::ConfigureEndpointCmd);
    cfgCmd.setSlotId(flashDev->getSlotId());
    cmdOk = hc->submitCommand(cfgCmd, compEvent);
    TEST_ASSERT(cmdOk && compEvent.getCompletionCode() == xhci::CompCode::Success, "ConfigureEndpointCmd must succeed");

    // Stage 5: Control Transfer Processing (Setup Stage + Data Stage + Status Stage)
    USB_DEFAULT_PIPE_SETUP_PACKET setupStatus{};
    setupStatus.bmRequestType = RequestType::Standard | RequestType::RecipientDevice | RequestType::DirectionIn;
    setupStatus.bRequest = StandardRequest::GET_STATUS;
    setupStatus.wLength = 2;
    uint8_t statusBuf[2]{};
    uint32_t transferred = 0;
    auto usbdSt = hc->executeControlTransfer(flashDev->getSlotId(), setupStatus, statusBuf, sizeof(statusBuf), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success, "Control transfer GET_STATUS must succeed");
    TEST_ASSERT(transferred == 2, "Transferred bytes for GET_STATUS must be 2");
    TEST_ASSERT((statusBuf[0] & 0x01) != 0, "Self-powered status bit must be set");

    USB_DEFAULT_PIPE_SETUP_PACKET setupGetCfg{};
    setupGetCfg.bmRequestType = RequestType::Standard | RequestType::RecipientDevice | RequestType::DirectionIn;
    setupGetCfg.bRequest = StandardRequest::GET_CONFIGURATION;
    setupGetCfg.wLength = 1;
    uint8_t cfgVal = 0;
    usbdSt = hc->executeControlTransfer(flashDev->getSlotId(), setupGetCfg, &cfgVal, 1, transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && cfgVal == 1, "GET_CONFIGURATION must return active configuration 1");

    // Stage 6: USB Mass Storage Bulk-Only Transport (BOT) SCSI Protocol
    auto msc = std::dynamic_pointer_cast<UsbMassStorageDevice>(flashDev);
    TEST_ASSERT(msc != nullptr, "Must cast to UsbMassStorageDevice");
    TEST_ASSERT(msc->getCapacitySectors() == 65536, "Flash drive capacity must be 65536 sectors");

    // BOT CBW for SCSI INQUIRY (0x12)
    uint8_t inqCbw[31]{};
    *reinterpret_cast<uint32_t*>(inqCbw) = 0x43425355; // 'USBC'
    *reinterpret_cast<uint32_t*>(inqCbw + 4) = 0x88776655; // Tag
    *reinterpret_cast<uint32_t*>(inqCbw + 8) = 36; // 36 bytes expected
    inqCbw[12] = 0x80; // Data IN
    inqCbw[14] = 6;    // CDB length 6
    inqCbw[15] = 0x12; // INQUIRY
    inqCbw[19] = 36;

    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x01, inqCbw, sizeof(inqCbw), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 31, "CBW transfer must succeed");

    uint8_t inqData[36]{};
    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x82, inqData, sizeof(inqData), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 36, "Inquiry data reception must succeed");
    TEST_ASSERT(std::memcmp(&inqData[8], "SanDisk ", 8) == 0, "SCSI Vendor must be SanDisk");

    uint8_t mscCsw[13]{};
    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x82, mscCsw, sizeof(mscCsw), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 13, "CSW reception must succeed");
    TEST_ASSERT(*reinterpret_cast<uint32_t*>(mscCsw) == 0x53425355, "CSW signature must be 'USBS'");
    TEST_ASSERT(*reinterpret_cast<uint32_t*>(mscCsw + 4) == 0x88776655, "CSW tag must match CBW tag");
    TEST_ASSERT(mscCsw[12] == 0, "CSW status must be 0 (Passed)");

    // BOT Sector Write (WRITE 10) and Sector Read (READ 10)
    uint8_t writeCbw[31]{};
    *reinterpret_cast<uint32_t*>(writeCbw) = 0x43425355;
    *reinterpret_cast<uint32_t*>(writeCbw + 4) = 0x99001122;
    *reinterpret_cast<uint32_t*>(writeCbw + 8) = 512;
    writeCbw[12] = 0x00; // Data OUT
    writeCbw[14] = 10;   // CDB len 10
    writeCbw[15] = 0x2A; // WRITE 10
    writeCbw[17] = 0; writeCbw[18] = 0; writeCbw[19] = 0; writeCbw[20] = 50; // LBA 50
    writeCbw[22] = 0; writeCbw[23] = 1; // 1 sector

    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x01, writeCbw, sizeof(writeCbw), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success, "WRITE 10 CBW must succeed");

    std::vector<uint8_t> testSector(512, 0xAB);
    testSector[0] = 'M'; testSector[1] = 'I'; testSector[2] = 'C'; testSector[3] = 'A';
    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x01, testSector.data(), 512, transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 512, "Sector write payload transfer must succeed");

    // READ 10 on LBA 50
    uint8_t readCbw[31]{};
    *reinterpret_cast<uint32_t*>(readCbw) = 0x43425355;
    *reinterpret_cast<uint32_t*>(readCbw + 4) = 0x99001123;
    *reinterpret_cast<uint32_t*>(readCbw + 8) = 512;
    readCbw[12] = 0x80; // Data IN
    readCbw[14] = 10;   // CDB len 10
    readCbw[15] = 0x28; // READ 10
    readCbw[17] = 0; readCbw[18] = 0; readCbw[19] = 0; readCbw[20] = 50; // LBA 50
    readCbw[22] = 0; readCbw[23] = 1;

    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x01, readCbw, sizeof(readCbw), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success, "READ 10 CBW must succeed");

    std::vector<uint8_t> readSector(512, 0);
    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x82, readSector.data(), 512, transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 512, "Sector read payload transfer must succeed");
    TEST_ASSERT(std::memcmp(readSector.data(), testSector.data(), 512) == 0, "Read data must exactly match written sector payload");

    // Stage 7: USB Human Interface Device (HID) Mouse Event Pipeline
    auto hidMouse = std::dynamic_pointer_cast<UsbHidMouseDevice>(mouseDev);
    TEST_ASSERT(hidMouse != nullptr, "Must cast to UsbHidMouseDevice");
    TEST_ASSERT(hidMouse->getDeviceDescriptor().bDeviceClass == ClassCode::HID, "Mouse class must be HID (0x03)");

    hidMouse->queueInputEvent(0x01 | 0x02, -25, 40, 2); // Left+Right buttons, dx=-25, dy=40, wheel=2
    UsbMouseReport mouseRep{};
    usbdSt = hc->executeTransfer(mouseDev->getSlotId(), 0x81, reinterpret_cast<uint8_t*>(&mouseRep), sizeof(mouseRep), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == sizeof(UsbMouseReport), "HID report read must succeed");
    TEST_ASSERT(mouseRep.buttons == 0x03, "Buttons must be Left+Right (0x03)");
    TEST_ASSERT(mouseRep.xDelta == -25, "X delta must match -25");
    TEST_ASSERT(mouseRep.yDelta == 40, "Y delta must match 40");
    TEST_ASSERT(mouseRep.wheel == 2, "Wheel delta must match 2");

    // Stage 8: USB CDC-ACM Virtual Serial Port (COM3)
    auto cdc = std::dynamic_pointer_cast<UsbCdcAcmDevice>(serialDev);
    TEST_ASSERT(cdc != nullptr, "Must cast to UsbCdcAcmDevice");

    cdc->writeSerialData("AT+GMR\r\n");
    uint8_t cdcInBuf[32]{};
    usbdSt = hc->executeTransfer(serialDev->getSlotId(), 0x83, cdcInBuf, sizeof(cdcInBuf), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 8, "CDC serial data read must succeed");
    TEST_ASSERT(std::string(reinterpret_cast<char*>(cdcInBuf), transferred) == "AT+GMR\r\n", "Serial received text must match AT+GMR");

    const char* hostMsg = "OK\r\n";
    usbdSt = hc->executeTransfer(serialDev->getSlotId(), 0x02, const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hostMsg)), 4, transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 4, "Host to device CDC transmission must succeed");
    TEST_ASSERT(cdc->readReceivedSerialData() == "OK\r\n", "Device received buffer must match host sent message");

    // Stage 9: WinUSB Userland Client Architecture (winusb.dll Parity)
    win32::HANDLE hDev1 = reinterpret_cast<win32::HANDLE>(1);
    WINUSB_INTERFACE_HANDLE hWinUsb = nullptr;
    auto bInit = WinUsb_Initialize(hDev1, &hWinUsb);
    TEST_ASSERT(bInit && hWinUsb != nullptr, "WinUsb_Initialize must return TRUE with valid handle");

    USB_INTERFACE_DESCRIPTOR ifaceDesc{};
    auto bQuery = WinUsb_QueryInterfaceSettings(hWinUsb, 0, &ifaceDesc);
    TEST_ASSERT(bQuery, "WinUsb_QueryInterfaceSettings must succeed");
    TEST_ASSERT(ifaceDesc.bInterfaceClass == ClassCode::MassStorage, "Interface class must be Mass Storage");

    WINUSB_PIPE_INFORMATION pipeInfo{};
    auto bPipe0 = WinUsb_QueryPipe(hWinUsb, 0, 0, &pipeInfo);
    TEST_ASSERT(bPipe0 && pipeInfo.PipeId == 0x01, "First pipe must be EP1 OUT");
    TEST_ASSERT(pipeInfo.PipeType == 2, "Pipe type must be Bulk (2)");

    uint32_t timeoutVal = 4500;
    auto bSetPol = WinUsb_SetPipePolicy(hWinUsb, 0x01, WinUsbPolicy::PIPE_TRANSFER_TIMEOUT, sizeof(timeoutVal), &timeoutVal);
    TEST_ASSERT(bSetPol, "WinUsb_SetPipePolicy must return TRUE");

    uint32_t retrievedTimeout = 0;
    ULONG polLen = sizeof(retrievedTimeout);
    auto bGetPol = WinUsb_GetPipePolicy(hWinUsb, 0x01, WinUsbPolicy::PIPE_TRANSFER_TIMEOUT, &polLen, &retrievedTimeout);
    TEST_ASSERT(bGetPol && retrievedTimeout == 4500, "Retrieved pipe timeout policy must match 4500ms");

    auto bFree = WinUsb_Free(hWinUsb);
    TEST_ASSERT(bFree, "WinUsb_Free must return TRUE");

    // Stage 10: Dynamic Hotplug Attachment, Port Reset & Removal
    bool hpAttach = sub.hotplugAttach(4, "mouse");
    TEST_ASSERT(hpAttach, "Hotplug attach to Port 4 must succeed");
    auto p4Dev = rh->getAttachedDevice(4);
    TEST_ASSERT(p4Dev != nullptr, "Port 4 device must not be null");
    TEST_ASSERT(rh->getPortStatus(4).connected && rh->getPortStatus(4).enabled, "Port 4 must be connected and enabled");
    TEST_ASSERT(p4Dev->getDeviceDescriptor().bDeviceClass == ClassCode::HID, "Attached device must be HID mouse");

    bool hpDetach = sub.hotplugDetach(4);
    TEST_ASSERT(hpDetach, "Hotplug detach from Port 4 must succeed");
    TEST_ASSERT(rh->getAttachedDevice(4) == nullptr, "Port 4 must be empty after detachment");
    TEST_ASSERT(!rh->getPortStatus(4).connected, "Port 4 connected flag must be false");

    // Stage 11: Dynamic Loader Exports & Service Control Manager Parity
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("winusb.dll", "WinUsb_Initialize") != nullptr, "winusb.dll WinUsb_Initialize export must be registered");
    TEST_ASSERT(ldr.getExport("winusb.dll", "WinUsb_ReadPipe") != nullptr, "winusb.dll WinUsb_ReadPipe export must be registered");
    TEST_ASSERT(ldr.getExport("winusb.dll", "WinUsb_WritePipe") != nullptr, "winusb.dll WinUsb_WritePipe export must be registered");

    auto xhciSvc = scm::ServiceControlManager::get().getServiceRecord(L"usbxhci");
    TEST_ASSERT(xhciSvc != nullptr, "usbxhci service record must exist in SCM");
    TEST_ASSERT(xhciSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "usbxhci service type must be kernel driver");

    auto hubSvc = scm::ServiceControlManager::get().getServiceRecord(L"usbhub3");
    TEST_ASSERT(hubSvc != nullptr, "usbhub3 service record must exist in SCM");

    // Stage 12: Version Database Parity
    auto winusbVer = version::VersionDatabase::Instance().GetModuleInfo("winusb.dll");
    TEST_ASSERT(winusbVer != nullptr, "winusb.dll must be registered in Version Database");
    TEST_ASSERT(winusbVer->stringTable.count("FileVersion") > 0, "winusb.dll FileVersion must exist");

    std::cout << "[TEST] Suite 151: Universal Serial Bus (USB 3.2 / xHCI) & Hub Subsystem PASSED.\n";
}

void Test_USB4_Thunderbolt4_ProtocolTunneling_Subsystem() {
    std::cout << "[TEST] Starting Suite 160: USB4 2.0 & Thunderbolt 4 Protocol Tunneling Subsystem...\n";

    // 1. Initialize Subsystem & Register Components
    usb4::InitializeUsb4Subsystem();
    auto& usb4Sub = usb4::TitanUsb4Subsystem::Instance();
    TEST_ASSERT(usb4Sub.isInitialized() == true, "TitanUSB4 subsystem must be initialized");

    // Stage 1: PCIe Miniport Binding (Bus 00:07.0)
    auto pciDev = pci::TitanPciSubsystem::Instance().findDevice(pci::PciAddress(0, 7, 0));
    TEST_ASSERT(pciDev != nullptr, "TitanUSB4 PCIe device must be registered at 00:07.0");
    TEST_ASSERT(pciDev->getVendorId() == 0x8086, "USB4 Host Router Vendor ID must be 0x8086 (Intel / Titan)");
    TEST_ASSERT(pciDev->getDeviceId() == 0x9A1B, "USB4 Host Router Device ID must be 0x9A1B (Arrow Lake USB4 Host Router)");
    TEST_ASSERT(pciDev->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::SerialBus), "Base class must be SerialBus");
    TEST_ASSERT(pciDev->getProgIf() == 0x40, "Programming Interface must be 0x40 (USB4 Host Interface)");

    // Stage 2: Host Router Capabilities & USB4 2.0 Version Discovery
    auto topo = usb4Sub.getTopology();
    TEST_ASSERT(!topo.empty(), "Topology must contain Host Router at root");
    const auto& hostRouter = topo[0];
    TEST_ASSERT(hostRouter.routerId == 0, "Host Router ID must be 0");
    TEST_ASSERT(hostRouter.depth == 0, "Host Router topology depth must be 0");
    TEST_ASSERT(hostRouter.negotiatedBandwidthGbps >= 80, "Host Router base link bandwidth must be at least 80 Gbps");
    TEST_ASSERT(hostRouter.adapters.size() >= 5, "Host Router must contain at least 5 adapters (HI, PCIe, DP, USB3, Lane)");

    // Stage 3: Physical Layer Signaling & Link Modes (80 Gbps symmetric PAM3)
    TEST_ASSERT(usb4Sub.getLinkSpeed() == usb4::Usb4LinkSpeed::Gen4_80G_Symmetric, "Default link speed must be 80 Gbps symmetric PAM3");
    TEST_ASSERT(usb4Sub.isAsymmetricModeEnabled() == false, "Asymmetric PAM3 mode must be disabled by default");

    // Stage 4: Dynamic PAM3 Asymmetric Mode Toggle (120 Gbps downstream / 40 Gbps upstream)
    usb4Sub.setAsymmetricMode(true);
    TEST_ASSERT(usb4Sub.isAsymmetricModeEnabled() == true, "Asymmetric PAM3 mode must report enabled");
    TEST_ASSERT(usb4Sub.getLinkSpeed() == usb4::Usb4LinkSpeed::Gen4_120G_Asymmetric, "Link speed must update to Gen4 120 Gbps Asymmetric");
    auto topoAsym = usb4Sub.getTopology();
    TEST_ASSERT(topoAsym[0].negotiatedBandwidthGbps == 120, "Host router negotiated bandwidth must scale to 120 Gbps");
    usb4Sub.setAsymmetricMode(false);
    TEST_ASSERT(usb4Sub.getLinkSpeed() == usb4::Usb4LinkSpeed::Gen4_80G_Symmetric, "Link speed must restore to 80 Gbps Symmetric");

    // Stage 5: Router Topology Tree Discovery (Host -> Tier 1 Dock -> Tier 2 eGPU)
    TEST_ASSERT(usb4Sub.getConnectedRoutersCount() >= 3, "Subsystem must discover at least 3 cascaded routers");
    const auto& dockRouter = topo[1];
    TEST_ASSERT(dockRouter.routerId == 1, "Tier 1 Router ID must be 1");
    TEST_ASSERT(dockRouter.depth == 1, "Tier 1 Router depth must be 1");
    TEST_ASSERT(dockRouter.modelName.find("Docking Station") != std::string::npos, "Router 1 must be Quantum 80G Dock");

    const auto& egpuRouter = topo[2];
    TEST_ASSERT(egpuRouter.routerId == 2, "Tier 2 Router ID must be 2");
    TEST_ASSERT(egpuRouter.depth == 2, "Tier 2 Router depth must be 2");
    TEST_ASSERT(egpuRouter.modelName.find("eGPU") != std::string::npos, "Router 2 must be eGPU Accelerator");

    // Stage 6: Peripheral UUID Interrogation and Metadata Inspection
    TEST_ASSERT(dockRouter.deviceUuid == "80860001-BEEF-4000-8000-001A7DDA7201", "Dock UUID must match registered descriptor");
    TEST_ASSERT(egpuRouter.deviceUuid == "10DE0002-CAFE-4000-8000-001A7DDA7202", "eGPU UUID must match registered descriptor");

    // Stage 7: Thunderbolt Security Level Policy Enforcement (SL0..SL3)
    TEST_ASSERT(usb4Sub.getSecurityLevel() == usb4::Usb4SecurityLevel::SL2_SecureConnection, "Default security level must be SL2 (Secure Connection)");
    usb4Sub.setSecurityLevel(usb4::Usb4SecurityLevel::SL3_DisplayPortOnly);
    TEST_ASSERT(usb4Sub.getSecurityLevel() == usb4::Usb4SecurityLevel::SL3_DisplayPortOnly, "Security level must update to SL3");
    // Under SL3, PCIe path creation must be rejected
    uint16_t blockedHop = 0;
    auto blockedSt = usb4Sub.createPath(0, 1, 1, 1, usb4::Usb4PathType::PCIe, 16000, 32, blockedHop);
    TEST_ASSERT(blockedSt == NtStatus::AccessDenied, "PCIe path creation must be rejected under SL3 (DisplayPort only)");
    usb4Sub.setSecurityLevel(usb4::Usb4SecurityLevel::SL2_SecureConnection);

    // Stage 8: SL2 Cryptographic Peripheral Authorization & Challenge-Response
    bool authOk = usb4Sub.authorizeDevice("10DE0002-CAFE-4000-8000-001A7DDA7202");
    TEST_ASSERT(authOk == true, "Peripheral authorization for valid UUID must succeed");
    bool badAuth = usb4Sub.authorizeDevice("00000000-0000-0000-0000-000000000000");
    TEST_ASSERT(badAuth == false, "Peripheral authorization for invalid UUID must fail");

    // Stage 9: PCIe Protocol Tunneling Adapter Configuration & Path Establishment (USB4_PATH)
    auto activePaths = usb4Sub.getActivePaths();
    TEST_ASSERT(!activePaths.empty(), "Active paths list must contain pre-configured default tunnels");
    bool foundPciePath = false;
    for (const auto& p : activePaths) {
        if (p.hopId == 8 && p.pathType == usb4::Usb4PathType::PCIe) {
            foundPciePath = true;
            TEST_ASSERT(p.allocatedBandwidthMbps >= 32000, "PCIe path bandwidth must be >= 32 Gbps");
            TEST_ASSERT(p.creditsAllocated >= 64, "PCIe path credits must be >= 64");
            TEST_ASSERT(p.isActive == true, "PCIe path must be in active state");
            break;
        }
    }
    TEST_ASSERT(foundPciePath == true, "Hop ID 8 PCIe tunneling path must exist");

    // Stage 10: PCIe Transaction Layer Packet (TLP) Encapsulation, Transmission & Decapsulation
    std::vector<uint8_t> tlpPayload = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF };
    bool txPcieOk = usb4Sub.tunnelPciePacket(8, tlpPayload);
    TEST_ASSERT(txPcieOk == true, "Tunneling PCIe TLP over Hop ID 8 must succeed");

    usb4::PcieTunnelEngine engine;
    auto encapsulated = engine.encapsulateTlp(8, tlpPayload);
    TEST_ASSERT(encapsulated.size() > tlpPayload.size(), "Encapsulated packet must include USB4 transport framing");
    uint16_t decapsHop = 0;
    std::vector<uint8_t> decapsTlp;
    bool decapsOk = engine.decapsulateTlp(encapsulated, decapsHop, decapsTlp);
    TEST_ASSERT(decapsOk == true, "Decapsulation of USB4 transport frame must succeed");
    TEST_ASSERT(decapsHop == 8, "Decapsulated Hop ID must match original");
    TEST_ASSERT(decapsTlp == tlpPayload, "Decapsulated TLP payload must match transmitted data byte-for-byte");

    // Stage 11: DisplayPort 2.1 Video Tunneling Path Setup & Bandwidth Verification
    bool txDpOk = usb4Sub.tunnelDpPacket(9, 8192);
    TEST_ASSERT(txDpOk == true, "Tunneling DisplayPort video frame over Hop ID 9 must succeed");

    // Stage 12: SuperSpeed USB 3.2 Protocol Tunneling
    bool txUsbOk = usb4Sub.tunnelUsb3Packet(10, 2048);
    TEST_ASSERT(txUsbOk == true, "Tunneling SuperSpeed USB 3.2 frame over Hop ID 10 must succeed");

    auto stats = usb4Sub.getStatistics();
    TEST_ASSERT(stats.totalTransmittedPackets >= 3, "Transmitted packet counter must reflect PCIe, DP, and USB3 traffic");
    TEST_ASSERT(stats.pcieTunneledBytes >= tlpPayload.size(), "PCIe tunneled byte counter must increment");
    TEST_ASSERT(stats.dpTunneledBytes >= 8192, "DisplayPort tunneled byte counter must increment");
    TEST_ASSERT(stats.usb3TunneledBytes >= 2048, "USB 3.2 tunneled byte counter must increment");

    // Stage 13: Dynamic Loader C ABI Exports Verification (usb4host.sys, thunderbolt.sys, usb4router.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("usb4host.sys", "Usb4HostInitialize") != nullptr, "Usb4HostInitialize export must exist");
    TEST_ASSERT(ldr.getExport("usb4host.sys", "Usb4HostEnumerateTopology") != nullptr, "Usb4HostEnumerateTopology export must exist");
    TEST_ASSERT(ldr.getExport("usb4host.sys", "Usb4HostCreatePath") != nullptr, "Usb4HostCreatePath export must exist");
    TEST_ASSERT(ldr.getExport("usb4host.sys", "Usb4HostDestroyPath") != nullptr, "Usb4HostDestroyPath export must exist");
    TEST_ASSERT(ldr.getExport("usb4host.sys", "Usb4HostGetRouterCapabilities") != nullptr, "Usb4HostGetRouterCapabilities export must exist");
    TEST_ASSERT(ldr.getExport("thunderbolt.sys", "ThunderboltGetSecurityLevel") != nullptr, "ThunderboltGetSecurityLevel export must exist");
    TEST_ASSERT(ldr.getExport("thunderbolt.sys", "ThunderboltSetSecurityLevel") != nullptr, "ThunderboltSetSecurityLevel export must exist");
    TEST_ASSERT(ldr.getExport("thunderbolt.sys", "ThunderboltAuthorizeDevice") != nullptr, "ThunderboltAuthorizeDevice export must exist");
    TEST_ASSERT(ldr.getExport("usb4router.sys", "Usb4TunnelPciePacket") != nullptr, "Usb4TunnelPciePacket export must exist");

    // Direct C ABI Invocation Checks
    uint32_t rCount = 0;
    TEST_ASSERT(usb4::Usb4HostEnumerateTopology(&rCount) == 0 && rCount >= 3, "Usb4HostEnumerateTopology C ABI call must succeed");
    uint8_t secLvl = 0;
    TEST_ASSERT(usb4::ThunderboltGetSecurityLevel(&secLvl) == 0 && secLvl == 2, "ThunderboltGetSecurityLevel C ABI call must return SL2");
    TEST_ASSERT(usb4::ThunderboltAuthorizeDevice("10DE0002-CAFE-4000-8000-001A7DDA7202") == 0, "ThunderboltAuthorizeDevice C ABI call must succeed");

    // Stage 14: SCM Service Records & Version Database Registrations
    auto hostSvc = scm::ServiceControlManager::get().getServiceRecord(L"usb4host");
    TEST_ASSERT(hostSvc != nullptr, "usb4host service record must exist in SCM");
    TEST_ASSERT(hostSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "usb4host must be a kernel driver");
    TEST_ASSERT(hostSvc->startType == scm::SERVICE_BOOT_START, "usb4host must have boot start type");

    auto tbtSvc = scm::ServiceControlManager::get().getServiceRecord(L"thunderbolt");
    TEST_ASSERT(tbtSvc != nullptr, "thunderbolt service record must exist in SCM");
    TEST_ASSERT(tbtSvc->startType == scm::SERVICE_BOOT_START, "thunderbolt must have boot start type");

    auto routerSvc = scm::ServiceControlManager::get().getServiceRecord(L"usb4router");
    TEST_ASSERT(routerSvc != nullptr, "usb4router service record must exist in SCM");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("usb4host.sys") != nullptr, "usb4host.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("thunderbolt.sys") != nullptr, "thunderbolt.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("usb4router.sys") != nullptr, "usb4router.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 160: USB4 2.0 & Thunderbolt 4 Protocol Tunneling Subsystem PASSED.\n";
}

void Test_WindowsDriverFrameworks_WDF_Subsystem() {
    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 149: Windows Driver Frameworks (KMDF & UMDF 2.0) Subsystem     \n";
    std::cout << "========================================================================\n";

    using namespace micant::wdf;

    // Initialize subsystem exports & services
    InitializeWdfSubsystemExports();
    auto& engine = TitanWdfEngine::Instance();

    // Stage 1: Dynamic Loader & Service Registration Verification
    auto& loader = micant::ldr::DynamicLoader::get();
    TEST_ASSERT(loader.getExport("Wdf01000.sys", "WdfDriverCreate") != nullptr, "Wdf01000.sys must export WdfDriverCreate");
    TEST_ASSERT(loader.getExport("Wdf01000.sys", "WdfDeviceCreate") != nullptr, "Wdf01000.sys must export WdfDeviceCreate");
    TEST_ASSERT(loader.getExport("Wdf01000.sys", "WdfIoQueueCreate") != nullptr, "Wdf01000.sys must export WdfIoQueueCreate");
    TEST_ASSERT(loader.getExport("wdfldr.sys", "WdfVersionBind") != nullptr, "wdfldr.sys must export WdfVersionBind");
    TEST_ASSERT(loader.getExport("WUDFx02000.dll", "WdfDriverCreate") != nullptr, "WUDFx02000.dll must export WdfDriverCreate");

    auto& scm = micant::scm::ServiceControlManager::get();
    TEST_ASSERT(scm.getServiceRecord(L"Wdf01000") != nullptr, "Wdf01000 kernel driver service must exist in SCM");
    TEST_ASSERT(scm.getServiceRecord(L"WUDFHost") != nullptr, "WUDFHost service must exist in SCM");

    // Stage 2: Driver Creation & Context Attributes
    struct SAMPLE_DRIVER_CONTEXT {
        uint32_t Magic;
        uint32_t Signature;
    };
    WDF_OBJECT_CONTEXT_TYPE_INFO ctxInfo{};
    ctxInfo.Size = sizeof(WDF_OBJECT_CONTEXT_TYPE_INFO);
    ctxInfo.ContextName = "SAMPLE_DRIVER_CONTEXT";
    ctxInfo.ContextSize = sizeof(SAMPLE_DRIVER_CONTEXT);

    WDF_OBJECT_ATTRIBUTES drvAttr{};
    WDF_OBJECT_ATTRIBUTES_INIT(&drvAttr);
    drvAttr.ContextTypeInfo = &ctxInfo;

    WDF_DRIVER_CONFIG drvConfig{};
    WDF_DRIVER_CONFIG_INIT(&drvConfig, nullptr);

    WDFDRIVER hDriver = nullptr;
    NTSTATUS status = WdfDriverCreate(
        nullptr,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\TitanSample",
        &drvAttr,
        &drvConfig,
        &hDriver
    );
    TEST_ASSERT(NT_SUCCESS(status) && hDriver != nullptr, "WdfDriverCreate must succeed");

    auto* ctx = reinterpret_cast<SAMPLE_DRIVER_CONTEXT*>(WdfObjectGetTypedContextWorker(hDriver, &ctxInfo));
    TEST_ASSERT(ctx != nullptr, "WdfObjectGetTypedContextWorker must return valid driver context");
    ctx->Magic = 0x57444631; // 'WDF1'
    ctx->Signature = 0xAABBCCDD;
    TEST_ASSERT(ctx->Magic == 0x57444631, "Context memory read/write validation passed");

    // Stage 3: Functional Device Creation & PnP State Machine
    bool prepHwCalled = false;
    bool d0EntryCalled = false;
    bool d0ExitCalled = false;

    WDFDEVICE_INIT devInit{};
    devInit.DeviceName = "\\Device\\TitanVirtualPci0";
    devInit.HardwareId = "PCI\\VEN_10EE&DEV_MICA";
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&devInit.PnpPowerCallbacks);
    devInit.PnpPowerCallbacks.EvtDevicePrepareHardware = [&](WDFDEVICE) -> NTSTATUS {
        prepHwCalled = true;
        return STATUS_SUCCESS;
    };
    devInit.PnpPowerCallbacks.EvtDeviceD0Entry = [&](WDFDEVICE, WDF_DEVICE_POWER_STATE) -> NTSTATUS {
        d0EntryCalled = true;
        return STATUS_SUCCESS;
    };
    devInit.PnpPowerCallbacks.EvtDeviceD0Exit = [&](WDFDEVICE, WDF_DEVICE_POWER_STATE) -> NTSTATUS {
        d0ExitCalled = true;
        return STATUS_SUCCESS;
    };

    WDFDEVICE_INIT* pDevInit = &devInit;
    WDFDEVICE hDevice = nullptr;
    status = WdfDeviceCreate(&pDevInit, nullptr, &hDevice);
    TEST_ASSERT(NT_SUCCESS(status) && hDevice != nullptr, "WdfDeviceCreate must succeed");
    TEST_ASSERT(pDevInit == nullptr, "DeviceInit must be consumed by WdfDeviceCreate");
    TEST_ASSERT(prepHwCalled, "EvtDevicePrepareHardware must be invoked during device creation");
    TEST_ASSERT(d0EntryCalled, "EvtDeviceD0Entry must be invoked during initial D0 start");

    auto* devRec = reinterpret_cast<WdfDeviceRecord*>(hDevice);
    TEST_ASSERT(devRec->PnpState == WdfDevStatePnpStarted, "Device PnP state must be WdfDevStatePnpStarted");
    TEST_ASSERT(devRec->PowerState == WdfDevStatePowerD0, "Device Power state must be WdfDevStatePowerD0");

    // Stage 4: Sequential Queue Dispatching & Automatic Serialization
    WDF_IO_QUEUE_CONFIG seqCfg{};
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&seqCfg, WdfIoQueueDispatchSequential);
    seqCfg.EvtIoWrite = [](WDFQUEUE, WDFREQUEST, size_t) {};

    WDFQUEUE hSeqQueue = nullptr;
    status = WdfIoQueueCreate(hDevice, &seqCfg, nullptr, &hSeqQueue);
    TEST_ASSERT(NT_SUCCESS(status) && hSeqQueue != nullptr, "Sequential WdfIoQueueCreate must succeed");

    WDFREQUEST hReq1 = nullptr;
    WDFREQUEST hReq2 = nullptr;
    WdfRequestCreate(nullptr, nullptr, &hReq1);
    WdfRequestCreate(nullptr, nullptr, &hReq2);

    auto* r1 = reinterpret_cast<WdfRequestRecord*>(hReq1);
    auto* r2 = reinterpret_cast<WdfRequestRecord*>(hReq2);
    r1->Type = WdfRequestTypeWrite;
    r1->InputBuffer = {10, 20, 30};
    r2->Type = WdfRequestTypeWrite;
    r2->InputBuffer = {40, 50, 60};

    // Dispatch Req1
    engine.dispatchRequest(hSeqQueue, hReq1);
    auto* qRec = reinterpret_cast<WdfQueueRecord*>(hSeqQueue);
    TEST_ASSERT(qRec->InFlightRequests.size() == 1, "Sequential queue must have 1 in-flight request");
    TEST_ASSERT(qRec->PendingRequests.empty(), "Sequential queue must have 0 pending requests");

    // Dispatch Req2 while Req1 is still in-flight
    engine.dispatchRequest(hSeqQueue, hReq2);
    TEST_ASSERT(qRec->InFlightRequests.size() == 1, "Sequential queue must still have only 1 in-flight request");
    TEST_ASSERT(qRec->PendingRequests.size() == 1, "Sequential queue must hold Req2 as pending");

    // Complete Req1
    WdfRequestCompleteWithInformation(hReq1, STATUS_SUCCESS, 3);
    TEST_ASSERT(r1->IsCompleted, "Req1 must be marked completed");
    // After Req1 completes, Req2 must be automatically dispatched!
    TEST_ASSERT(qRec->InFlightRequests.size() == 1, "Req2 must have been promoted to in-flight");
    TEST_ASSERT(qRec->InFlightRequests[0] == r2, "In-flight request must now be Req2");
    TEST_ASSERT(qRec->PendingRequests.empty(), "Pending queue must now be empty");

    // Complete Req2
    WdfRequestCompleteWithInformation(hReq2, STATUS_SUCCESS, 3);
    TEST_ASSERT(r2->IsCompleted, "Req2 must be marked completed");
    TEST_ASSERT(qRec->InFlightRequests.empty(), "Queue must have 0 in-flight requests after all complete");

    // Stage 5: Parallel Queue Dispatching
    WDF_IO_QUEUE_CONFIG parCfg{};
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&parCfg, WdfIoQueueDispatchParallel);
    WDFQUEUE hParQueue = nullptr;
    status = WdfIoQueueCreate(hDevice, &parCfg, nullptr, &hParQueue);
    TEST_ASSERT(NT_SUCCESS(status) && hParQueue != nullptr, "Parallel WdfIoQueueCreate must succeed");

    WDFREQUEST hPReq1 = nullptr;
    WDFREQUEST hPReq2 = nullptr;
    WdfRequestCreate(nullptr, nullptr, &hPReq1);
    WdfRequestCreate(nullptr, nullptr, &hPReq2);

    engine.dispatchRequest(hParQueue, hPReq1);
    engine.dispatchRequest(hParQueue, hPReq2);

    auto* parRec = reinterpret_cast<WdfQueueRecord*>(hParQueue);
    TEST_ASSERT(parRec->InFlightRequests.size() == 2, "Parallel queue must allow both requests in flight simultaneously");

    WdfRequestComplete(hPReq1, STATUS_SUCCESS);
    WdfRequestComplete(hPReq2, STATUS_SUCCESS);
    TEST_ASSERT(parRec->InFlightRequests.empty(), "Parallel queue in-flight cleared after completions");

    // Stage 6: Manual Queue Dispatching
    WDF_IO_QUEUE_CONFIG manCfg{};
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&manCfg, WdfIoQueueDispatchManual);
    WDFQUEUE hManQueue = nullptr;
    status = WdfIoQueueCreate(hDevice, &manCfg, nullptr, &hManQueue);
    TEST_ASSERT(NT_SUCCESS(status) && hManQueue != nullptr, "Manual WdfIoQueueCreate must succeed");

    WDFREQUEST hMReq = nullptr;
    WdfRequestCreate(nullptr, nullptr, &hMReq);
    engine.dispatchRequest(hManQueue, hMReq);

    auto* manRec = reinterpret_cast<WdfQueueRecord*>(hManQueue);
    TEST_ASSERT(manRec->PendingRequests.size() == 1, "Manual queue must hold request in pending queue");
    TEST_ASSERT(manRec->InFlightRequests.empty(), "Manual queue must not auto-dispatch requests");

    WDFREQUEST hRetrievedReq = nullptr;
    status = WdfIoQueueRetrieveNextRequest(hManQueue, &hRetrievedReq);
    TEST_ASSERT(NT_SUCCESS(status) && hRetrievedReq == hMReq, "WdfIoQueueRetrieveNextRequest must retrieve the queued request");
    WdfRequestComplete(hRetrievedReq, STATUS_SUCCESS);

    // Stage 7: Buffer Extraction & Verification
    WDFREQUEST hBufReq = nullptr;
    WdfRequestCreate(nullptr, nullptr, &hBufReq);
    auto* bufRec = reinterpret_cast<WdfRequestRecord*>(hBufReq);
    bufRec->InputBuffer = {'H', 'E', 'L', 'L', 'O'};
    bufRec->OutputBuffer.resize(16, 0);

    void* inBuf = nullptr;
    size_t inLen = 0;
    status = WdfRequestRetrieveInputBuffer(hBufReq, 5, &inBuf, &inLen);
    TEST_ASSERT(NT_SUCCESS(status) && inBuf != nullptr && inLen == 5, "WdfRequestRetrieveInputBuffer must succeed");
    TEST_ASSERT(std::memcmp(inBuf, "HELLO", 5) == 0, "Input buffer content match");

    void* outBuf = nullptr;
    size_t outLen = 0;
    status = WdfRequestRetrieveOutputBuffer(hBufReq, 16, &outBuf, &outLen);
    TEST_ASSERT(NT_SUCCESS(status) && outBuf != nullptr && outLen == 16, "WdfRequestRetrieveOutputBuffer must succeed");
    WdfRequestCompleteWithInformation(hBufReq, STATUS_SUCCESS, 5);

    // Stage 8: Power State Transitions
    status = WdfDeviceSetPowerState(hDevice, WdfDevStatePowerD3);
    TEST_ASSERT(NT_SUCCESS(status), "Transition to D3 must succeed");
    TEST_ASSERT(d0ExitCalled, "EvtDeviceD0Exit callback must be triggered on D3 transition");
    TEST_ASSERT(devRec->PowerState == WdfDevStatePowerD3, "PowerState must be D3");

    d0EntryCalled = false;
    status = WdfDeviceSetPowerState(hDevice, WdfDevStatePowerD0);
    TEST_ASSERT(NT_SUCCESS(status), "Transition to D0 must succeed");
    TEST_ASSERT(d0EntryCalled, "EvtDeviceD0Entry callback must be triggered on D0 resume");
    TEST_ASSERT(devRec->PowerState == WdfDevStatePowerD0, "PowerState must be restored to D0");

    // Stage 9: Memory Object Allocation
    WDFMEMORY hMem = nullptr;
    void* memPtr = nullptr;
    status = WdfMemoryCreate(nullptr, 0, 0x4D447672 /* 'MDvr' */, 256, &hMem, &memPtr);
    TEST_ASSERT(NT_SUCCESS(status) && hMem != nullptr && memPtr != nullptr, "WdfMemoryCreate must succeed");
    std::memset(memPtr, 0xAA, 256);
    TEST_ASSERT(static_cast<uint8_t*>(memPtr)[128] == 0xAA, "Memory write/read verified");

    // Stage 10: UMDF 2.0 User-Mode Driver Host & Fault Containment
    uint32_t umdfPid = 0;
    status = engine.startUmdfDriver("sensors.hid.dll", &umdfPid);
    TEST_ASSERT(NT_SUCCESS(status) && umdfPid > 0, "UMDF Host startup must succeed");

    status = engine.simulateUmdfCrash(umdfPid, true);
    TEST_ASSERT(NT_SUCCESS(status), "UMDF crash containment and reflector recovery must succeed without kernel panic");
    auto hosts = engine.getUmdfHostsSnapshot();
    TEST_ASSERT(hosts[umdfPid].CrashesRecovered == 1, "UMDF host recovery counter must increment");

    // Stage 11: Cascading Deletion
    bool cleanupCalled = false;
    WDF_OBJECT_ATTRIBUTES childAttr{};
    WDF_OBJECT_ATTRIBUTES_INIT(&childAttr);
    childAttr.ParentObject = hDevice;
    childAttr.EvtCleanupCallback = [&](WDFOBJECT) {
        cleanupCalled = true;
    };
    WDFREQUEST hChildReq = nullptr;
    WdfRequestCreate(&childAttr, nullptr, &hChildReq);

    WdfObjectDelete(hDevice);
    TEST_ASSERT(cleanupCalled, "Deleting parent device must automatically cascade and cleanup child objects");

    std::cout << "[TEST] Suite 149: Windows Driver Frameworks (KMDF & UMDF 2.0) Subsystem PASSED.\n";
}

void Test_WiFi7_WDI_NetAdapterCx_Subsystem() {
    std::cout << "[TEST] Starting Suite 159: Wi-Fi 7 (802.11be) & WDI NetAdapterCx Subsystem...\n";

    // Stage 1: Subsystem Initialization & PCIe Miniport Binding (BDF 00:06.0)
    wdi::InitializeWdiWiFiSubsystem();
    auto& wifiSub = wdi::TitanWiFiSubsystem::Instance();
    TEST_ASSERT(wifiSub.isInitialized() == true, "TitanWiFi subsystem must be initialized");
    TEST_ASSERT(wifiSub.getAdapterName().find("TitanWiFi 7") != std::string::npos, "Adapter name must identify as TitanWiFi 7");
    auto pciAddr = wifiSub.getPciAddress();
    TEST_ASSERT(pciAddr.bus == 0 && pciAddr.device == 6 && pciAddr.function == 0, "TitanWiFi must bind to PCIe BDF 00:06.0");

    // Stage 2: Station MAC Address Verification (Sovereign Titan Default)
    auto mac = wifiSub.getMacAddress();
    TEST_ASSERT(mac == wdi::WlanMacAddress::titanDefault(), "Station MAC address must match Sovereign default");
    TEST_ASSERT(mac.toString() == "00:1A:7D:DA:72:01", "Station MAC string must be 00:1A:7D:DA:72:01");
    TEST_ASSERT(mac.isBroadcast() == false, "Station MAC must not be broadcast");

    // Stage 3: Hardware Radio Power State Control (Airplane Mode Toggle)
    TEST_ASSERT(wifiSub.isRadioEnabled() == true, "Radio must be enabled by default");
    wifiSub.setRadioState(false);
    TEST_ASSERT(wifiSub.isRadioEnabled() == false, "Radio must be disabled upon request");
    wifiSub.setRadioState(true);
    TEST_ASSERT(wifiSub.isRadioEnabled() == true, "Radio must be restored to enabled");

    // Stage 4: WDI Task Execution Engine: WDI_TASK_SCAN
    auto scanSt = wifiSub.executeTask(wdi::WDI_TASK_SCAN);
    TEST_ASSERT(scanSt == NtStatus::Success, "WDI_TASK_SCAN execution must succeed");
    auto stats = wifiSub.getStatistics();
    TEST_ASSERT(stats.scanOperations >= 1, "Scan operations counter must increment");

    // Stage 5: WDI BSS Scan Catalog Queries (6 GHz 320 MHz, 5 GHz 160 MHz, 2.4 GHz)
    auto bssList = wifiSub.getScanResults();
    TEST_ASSERT(bssList.size() >= 3, "BSS scan catalog must return at least 3 discovered networks");
    bool found6g = false;
    bool found5g = false;
    bool found2g = false;
    for (const auto& b : bssList) {
        if (b.band == wdi::DOT11_BAND_6GHZ && b.channelWidth == wdi::DOT11_BW_320MHZ) found6g = true;
        if (b.band == wdi::DOT11_BAND_5GHZ && b.channelWidth == wdi::DOT11_BW_160MHZ) found5g = true;
        if (b.band == wdi::DOT11_BAND_2_4GHZ) found2g = true;
    }
    TEST_ASSERT(found6g == true, "Discovered BSS catalog must include 6 GHz 320 MHz Wi-Fi 7 network");
    TEST_ASSERT(found5g == true, "Discovered BSS catalog must include 5 GHz 160 MHz network");
    TEST_ASSERT(found2g == true, "Discovered BSS catalog must include 2.4 GHz legacy network");

    // Stage 6: Security Suite Verification (WPA3-Personal SAE & WPA3-Enterprise GCMP-256)
    bool hasWpa3Sae = false;
    for (const auto& b : bssList) {
        if (b.authType == wdi::DOT11_AUTH_WPA3_SAE && b.cipherType == wdi::DOT11_CIPHER_GCMP_256) {
            hasWpa3Sae = true;
            break;
        }
    }
    TEST_ASSERT(hasWpa3Sae == true, "Wi-Fi 7 network must require WPA3-SAE with GCMP-256 encryption");

    // Stage 7: Wi-Fi 7 Multi-Link Operation (MLO) Device Context
    auto mlo = wifiSub.getMloContext();
    TEST_ASSERT(mlo.mode == wdi::MloLinkMode::Mlmr, "MLO mode must be MLMR / STR (Simultaneous Transmit & Receive)");
    TEST_ASSERT(mlo.staMldMac == mac, "Station MLD MAC must match adapter MAC");
    TEST_ASSERT(mlo.links.size() >= 2, "MLO context must configure at least 2 bonded links");

    // Stage 8: MLO Affiliated Links Configuration
    const auto& link0 = mlo.links[0];
    TEST_ASSERT(link0.linkId == 0, "Link 0 ID must be 0");
    TEST_ASSERT(link0.band == wdi::DOT11_BAND_6GHZ, "Link 0 band must be 6 GHz");
    TEST_ASSERT(link0.channelWidthMhz == 320, "Link 0 channel width must be 320 MHz");
    TEST_ASSERT(link0.modulation == wdi::DOT11_MOD_4096QAM, "Link 0 modulation must be 4096-QAM");
    TEST_ASSERT(link0.phyRateBps >= 5'000'000'000ULL, "Link 0 PHY rate must exceed 5 Gbps");

    const auto& link1 = mlo.links[1];
    TEST_ASSERT(link1.linkId == 1, "Link 1 ID must be 1");
    TEST_ASSERT(link1.band == wdi::DOT11_BAND_5GHZ, "Link 1 band must be 5 GHz");
    TEST_ASSERT(link1.channelWidthMhz == 160, "Link 1 channel width must be 160 MHz");
    TEST_ASSERT(link1.modulation == wdi::DOT11_MOD_4096QAM, "Link 1 modulation must be 4096-QAM");

    // Stage 9: Aggregate MLO PHY Throughput Evaluation
    uint64_t aggPhy = mlo.getAggregatePhyRateBps();
    TEST_ASSERT(aggPhy >= 8'000'000'000ULL, "Aggregate MLO PHY throughput must exceed 8 Gbps (8.64 Gbps)");

    // Stage 10: WDI Connection Task Execution (WDI_TASK_CONNECT)
    auto connSt = wifiSub.executeTask(wdi::WDI_TASK_CONNECT);
    TEST_ASSERT(connSt == NtStatus::Success, "WDI_TASK_CONNECT must succeed");
    TEST_ASSERT(wifiSub.isConnected() == true, "Adapter state must transition to Connected");
    TEST_ASSERT(wifiSub.getConnectedSsid() == "Sovereign-Quantum-6G", "Connected SSID must be Sovereign-Quantum-6G");

    // Stage 11: NetAdapterCx Ring Queues (Tx/Rx) Packet Transmission & Byte Accounting
    std::vector<uint8_t> testPayload(512, 0xEE);
    bool txLink0 = wifiSub.transmitFrame(testPayload, 0);
    TEST_ASSERT(txLink0 == true, "Frame transmission over MLO link 0 must succeed");
    bool txLink1 = wifiSub.transmitFrame(testPayload, 1);
    TEST_ASSERT(txLink1 == true, "Frame transmission over MLO link 1 must succeed");

    auto statsAfter = wifiSub.getStatistics();
    TEST_ASSERT(statsAfter.txPackets >= 2, "Transmitted packet counter must increment");
    TEST_ASSERT(statsAfter.txBytes >= 1024, "Transmitted byte counter must reflect submitted frames");
    TEST_ASSERT(statsAfter.mloAggregatedBytes >= 1024, "MLO aggregated bytes must match total payload");

    // Stage 12: WDI Disconnection Task Execution (WDI_TASK_DISCONNECT)
    auto discSt = wifiSub.executeTask(wdi::WDI_TASK_DISCONNECT);
    TEST_ASSERT(discSt == NtStatus::Success, "WDI_TASK_DISCONNECT must succeed");
    TEST_ASSERT(wifiSub.isConnected() == false, "Adapter state must transition to Disconnected");

    // Stage 13: Dynamic Loader C ABI Exports Verification
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("wdiwifi.sys", "WdiInitialize") != nullptr, "wdiwifi.sys WdiInitialize must exist");
    TEST_ASSERT(ldr.getExport("wdiwifi.sys", "WdiRegisterMiniportDriver") != nullptr, "wdiwifi.sys WdiRegisterMiniportDriver must exist");
    TEST_ASSERT(ldr.getExport("wdiwifi.sys", "WdiSendTaskCommand") != nullptr, "wdiwifi.sys WdiSendTaskCommand must exist");
    TEST_ASSERT(ldr.getExport("wdiwifi.sys", "WdiGetAdapterCapabilities") != nullptr, "wdiwifi.sys WdiGetAdapterCapabilities must exist");
    TEST_ASSERT(ldr.getExport("netadaptercx.sys", "NetAdapterCreate") != nullptr, "netadaptercx.sys NetAdapterCreate must exist");
    TEST_ASSERT(ldr.getExport("netadaptercx.sys", "NetAdapterStart") != nullptr, "netadaptercx.sys NetAdapterStart must exist");
    TEST_ASSERT(ldr.getExport("titanwifi.sys", "TitanWiFiInitialize") != nullptr, "titanwifi.sys TitanWiFiInitialize must exist");
    TEST_ASSERT(ldr.getExport("titanwifi.sys", "TitanWiFiTransmitFrame") != nullptr, "titanwifi.sys TitanWiFiTransmitFrame must exist");

    // Stage 14: SCM Service Records & Version Database Verification
    auto wdiSvc = scm::ServiceControlManager::get().getServiceRecord(L"wdiwifi");
    TEST_ASSERT(wdiSvc != nullptr, "wdiwifi service record must exist in SCM");
    TEST_ASSERT(wdiSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "wdiwifi must be a kernel driver");
    TEST_ASSERT(wdiSvc->startType == scm::SERVICE_BOOT_START, "wdiwifi must have boot start type");

    auto netAdpSvc = scm::ServiceControlManager::get().getServiceRecord(L"netadaptercx");
    TEST_ASSERT(netAdpSvc != nullptr, "netadaptercx service record must exist in SCM");
    TEST_ASSERT(netAdpSvc->startType == scm::SERVICE_BOOT_START, "netadaptercx must have boot start type");

    auto titanWifiSvc = scm::ServiceControlManager::get().getServiceRecord(L"titanwifi");
    TEST_ASSERT(titanWifiSvc != nullptr, "titanwifi service record must exist in SCM");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("wdiwifi.sys") != nullptr, "wdiwifi.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("netadaptercx.sys") != nullptr, "netadaptercx.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("titanwifi.sys") != nullptr, "titanwifi.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 159: Wi-Fi 7 (802.11be) & WDI NetAdapterCx Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "              MicaNT-Drivers Master Test Suite Runner                   \n";
    std::cout << "       Validating all 26 Sovereign Hardware & Accelerator Drivers       \n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_ACPI_Platform_And_AML_Interpreter_Subsystem);
    RUN_TEST(Test_IntelAMX_ArmSME_MatrixAccelerator_Subsystem);
    RUN_TEST(Test_Bluetooth54_KernelPortDriver_Subsystem);
    RUN_TEST(Test_DirectStorage12_BypassIO_Subsystem);
    RUN_TEST(Test_IntelCET_HardwareEnforcedStackProtection_Subsystem);
    RUN_TEST(Test_ComputeExpressLink_CXL_HeterogeneousMemory_Subsystem);
    RUN_TEST(Test_IntelDSA_IAA_FastCopy_Subsystem);
    RUN_TEST(Test_WDDM32_GraphicsKernel_Subsystem);
    RUN_TEST(Test_IntelHighDefinitionAudio_USBAudio_Subsystem);
    RUN_TEST(Test_IntelThreadDirector_AMD_CPPC_HeterogeneousScheduling_Subsystem);
    RUN_TEST(Test_HardwareIOMMU_VTd_AMDVi_DMA_Remapping_Subsystem);
    RUN_TEST(Test_NDIS688_HighSpeedNetworking_Subsystem);
    RUN_TEST(Test_NeuralProcessingUnit_MCDM_DirectML_Subsystem);
    RUN_TEST(Test_NVMExpress_UniversalFlashStorage_Subsystem);
    RUN_TEST(Test_PCIExpress_PCIe_Bus_Subsystem);
    RUN_TEST(Test_MicrosoftPluton_SecurityProcessor_Subsystem);
    RUN_TEST(Test_PersistentMemory_NVDIMM_Optane_DAX_Subsystem);
    RUN_TEST(Test_IntelQAT_HardwareOffload_Subsystem);
    RUN_TEST(Test_RDMA_RoCEv2_InfiniBand_SMBDirect_Subsystem);
    RUN_TEST(Test_PCIeSRIOV_PASID_SharedVirtualAddressing_Subsystem);
    RUN_TEST(Test_ConfidentialComputing_TEE_Subsystem);
    RUN_TEST(Test_USBTypeC_UCSI_PowerDelivery31_Subsystem);
    RUN_TEST(Test_UniversalSerialBus_USB_xHCI_Subsystem);
    RUN_TEST(Test_USB4_Thunderbolt4_ProtocolTunneling_Subsystem);
    RUN_TEST(Test_WindowsDriverFrameworks_WDF_Subsystem);
    RUN_TEST(Test_WiFi7_WDI_NetAdapterCx_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
