// ============================================================================
// Standalone Driver Verification Test: amx (TitanMatrix / NexusAMX)
// Subsystem: Intel AMX & Arm SME Matrix Accelerator Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/amx.hpp"

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

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Intel AMX & Arm SME Matrix Accelerator Subsystem\n";
    std::cout << "       Codename: TitanMatrix / NexusAMX | Binary: intel_amx.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_IntelAMX_ArmSME_MatrixAccelerator_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
