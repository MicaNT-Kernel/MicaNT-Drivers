// ============================================================================
// Standalone Driver Verification Test: pluton (TitanPluton / AegisPluton)
// Subsystem: Microsoft Pluton On-Die Security Processor & Hardware RoT
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/pluton.hpp"

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

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Microsoft Pluton On-Die Security Processor & Hardware RoT\n";
    std::cout << "       Codename: TitanPluton / AegisPluton | Binary: pluton.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_MicrosoftPluton_SecurityProcessor_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
