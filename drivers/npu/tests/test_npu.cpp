// ============================================================================
// Standalone Driver Verification Test: npu (TitanNPU / NexusNPU)
// Subsystem: Neural Processing Unit & Microsoft Compute Driver Model (MCDM)
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/npu.hpp"

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

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Neural Processing Unit & Microsoft Compute Driver Model (MCDM)\n";
    std::cout << "       Codename: TitanNPU / NexusNPU | Binary: mcdm.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_NeuralProcessingUnit_MCDM_DirectML_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
