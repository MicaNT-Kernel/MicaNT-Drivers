// ============================================================================
// Standalone Driver Verification Test: hfi (TitanDirector / AegisScheduler)
// Subsystem: Intel Thread Director (HFI) & AMD CPPC Heterogeneous Scheduling
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/hfi.hpp"

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

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Intel Thread Director (HFI) & AMD CPPC Heterogeneous Scheduling\n";
    std::cout << "       Codename: TitanDirector / AegisScheduler | Binary: intel_hfi.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_IntelThreadDirector_AMD_CPPC_HeterogeneousScheduling_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
