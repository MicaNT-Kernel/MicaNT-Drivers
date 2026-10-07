// ============================================================================
// Standalone Driver Verification Test: qat (TitanQAT / NexusQAT)
// Subsystem: Intel QuickAssist Technology (QAT 2.0 / 4xxx) Crypto/Compression Offload
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/qat.hpp"

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

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Intel QuickAssist Technology (QAT 2.0 / 4xxx) Crypto/Compression Offload\n";
    std::cout << "       Codename: TitanQAT / NexusQAT | Binary: intel_qat.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_IntelQAT_HardwareOffload_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
