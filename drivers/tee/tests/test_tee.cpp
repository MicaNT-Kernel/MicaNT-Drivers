// ============================================================================
// Standalone Driver Verification Test: tee (TitanTEE / AegisTEE)
// Subsystem: Intel SGX/TDX & AMD SEV-SNP Confidential Computing Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/tee.hpp"

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

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Intel SGX/TDX & AMD SEV-SNP Confidential Computing Subsystem\n";
    std::cout << "       Codename: TitanTEE / AegisTEE | Binary: virtenclave.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_ConfidentialComputing_TEE_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
