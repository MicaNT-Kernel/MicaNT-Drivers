// ============================================================================
// Standalone Driver Verification Test: cet (TitanCET / AegisCET)
// Subsystem: Intel CET & Hardware-Enforced Stack Protection Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/cet.hpp"

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

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Intel CET & Hardware-Enforced Stack Protection Subsystem\n";
    std::cout << "       Codename: TitanCET / AegisCET | Binary: kshadowstack.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_IntelCET_HardwareEnforcedStackProtection_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
