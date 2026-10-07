// ============================================================================
// Standalone Driver Verification Test: dsa (TitanDSA / NexusDSA)
// Subsystem: Intel DSA & IAA Fast-Memory Streaming Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/dsa.hpp"

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

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Intel DSA & IAA Fast-Memory Streaming Subsystem\n";
    std::cout << "       Codename: TitanDSA / NexusDSA | Binary: intel_dsa.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_IntelDSA_IAA_FastCopy_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
