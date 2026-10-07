// ============================================================================
// Standalone Driver Verification Test: bypassio (TitanBypassIO / NexusBypassIO)
// Subsystem: DirectStorage 1.2 / BypassIO Storage Acceleration Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/bypassio.hpp"

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

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: DirectStorage 1.2 / BypassIO Storage Acceleration Subsystem\n";
    std::cout << "       Codename: TitanBypassIO / NexusBypassIO | Binary: bypassio.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_DirectStorage12_BypassIO_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
