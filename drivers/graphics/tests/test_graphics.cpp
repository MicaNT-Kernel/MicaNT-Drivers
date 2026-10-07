// ============================================================================
// Standalone Driver Verification Test: graphics (TitanWDDM / NexusWDDM)
// Subsystem: Windows Display Driver Model (WDDM 3.2) & Graphics Kernel
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/wddm.hpp"

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

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Windows Display Driver Model (WDDM 3.2) & Graphics Kernel\n";
    std::cout << "       Codename: TitanWDDM / NexusWDDM | Binary: dxgkrnl.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_WDDM32_GraphicsKernel_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
