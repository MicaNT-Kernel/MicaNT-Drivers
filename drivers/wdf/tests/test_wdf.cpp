// ============================================================================
// Standalone Driver Verification Test: wdf (TitanWDF / AegisWDF)
// Subsystem: Windows Driver Frameworks (KMDF v1.33 & UMDF 2.0) Core Library
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/wdf.hpp"

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

void Test_WindowsDriverFrameworks_WDF_Subsystem() {
    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 149: Windows Driver Frameworks (KMDF & UMDF 2.0) Subsystem     \n";
    std::cout << "========================================================================\n";

    using namespace micant::wdf;

    // Initialize subsystem exports & services
    InitializeWdfSubsystemExports();
    auto& engine = TitanWdfEngine::Instance();

    // Stage 1: Dynamic Loader & Service Registration Verification
    auto& loader = micant::ldr::DynamicLoader::get();
    TEST_ASSERT(loader.getExport("Wdf01000.sys", "WdfDriverCreate") != nullptr, "Wdf01000.sys must export WdfDriverCreate");
    TEST_ASSERT(loader.getExport("Wdf01000.sys", "WdfDeviceCreate") != nullptr, "Wdf01000.sys must export WdfDeviceCreate");
    TEST_ASSERT(loader.getExport("Wdf01000.sys", "WdfIoQueueCreate") != nullptr, "Wdf01000.sys must export WdfIoQueueCreate");
    TEST_ASSERT(loader.getExport("wdfldr.sys", "WdfVersionBind") != nullptr, "wdfldr.sys must export WdfVersionBind");
    TEST_ASSERT(loader.getExport("WUDFx02000.dll", "WdfDriverCreate") != nullptr, "WUDFx02000.dll must export WdfDriverCreate");

    auto& scm = micant::scm::ServiceControlManager::get();
    TEST_ASSERT(scm.getServiceRecord(L"Wdf01000") != nullptr, "Wdf01000 kernel driver service must exist in SCM");
    TEST_ASSERT(scm.getServiceRecord(L"WUDFHost") != nullptr, "WUDFHost service must exist in SCM");

    // Stage 2: Driver Creation & Context Attributes
    struct SAMPLE_DRIVER_CONTEXT {
        uint32_t Magic;
        uint32_t Signature;
    };
    WDF_OBJECT_CONTEXT_TYPE_INFO ctxInfo{};
    ctxInfo.Size = sizeof(WDF_OBJECT_CONTEXT_TYPE_INFO);
    ctxInfo.ContextName = "SAMPLE_DRIVER_CONTEXT";
    ctxInfo.ContextSize = sizeof(SAMPLE_DRIVER_CONTEXT);

    WDF_OBJECT_ATTRIBUTES drvAttr{};
    WDF_OBJECT_ATTRIBUTES_INIT(&drvAttr);
    drvAttr.ContextTypeInfo = &ctxInfo;

    WDF_DRIVER_CONFIG drvConfig{};
    WDF_DRIVER_CONFIG_INIT(&drvConfig, nullptr);

    WDFDRIVER hDriver = nullptr;
    NTSTATUS status = WdfDriverCreate(
        nullptr,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\TitanSample",
        &drvAttr,
        &drvConfig,
        &hDriver
    );
    TEST_ASSERT(NT_SUCCESS(status) && hDriver != nullptr, "WdfDriverCreate must succeed");

    auto* ctx = reinterpret_cast<SAMPLE_DRIVER_CONTEXT*>(WdfObjectGetTypedContextWorker(hDriver, &ctxInfo));
    TEST_ASSERT(ctx != nullptr, "WdfObjectGetTypedContextWorker must return valid driver context");
    ctx->Magic = 0x57444631; // 'WDF1'
    ctx->Signature = 0xAABBCCDD;
    TEST_ASSERT(ctx->Magic == 0x57444631, "Context memory read/write validation passed");

    // Stage 3: Functional Device Creation & PnP State Machine
    bool prepHwCalled = false;
    bool d0EntryCalled = false;
    bool d0ExitCalled = false;

    WDFDEVICE_INIT devInit{};
    devInit.DeviceName = "\\Device\\TitanVirtualPci0";
    devInit.HardwareId = "PCI\\VEN_10EE&DEV_MICA";
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&devInit.PnpPowerCallbacks);
    devInit.PnpPowerCallbacks.EvtDevicePrepareHardware = [&](WDFDEVICE) -> NTSTATUS {
        prepHwCalled = true;
        return STATUS_SUCCESS;
    };
    devInit.PnpPowerCallbacks.EvtDeviceD0Entry = [&](WDFDEVICE, WDF_DEVICE_POWER_STATE) -> NTSTATUS {
        d0EntryCalled = true;
        return STATUS_SUCCESS;
    };
    devInit.PnpPowerCallbacks.EvtDeviceD0Exit = [&](WDFDEVICE, WDF_DEVICE_POWER_STATE) -> NTSTATUS {
        d0ExitCalled = true;
        return STATUS_SUCCESS;
    };

    WDFDEVICE_INIT* pDevInit = &devInit;
    WDFDEVICE hDevice = nullptr;
    status = WdfDeviceCreate(&pDevInit, nullptr, &hDevice);
    TEST_ASSERT(NT_SUCCESS(status) && hDevice != nullptr, "WdfDeviceCreate must succeed");
    TEST_ASSERT(pDevInit == nullptr, "DeviceInit must be consumed by WdfDeviceCreate");
    TEST_ASSERT(prepHwCalled, "EvtDevicePrepareHardware must be invoked during device creation");
    TEST_ASSERT(d0EntryCalled, "EvtDeviceD0Entry must be invoked during initial D0 start");

    auto* devRec = reinterpret_cast<WdfDeviceRecord*>(hDevice);
    TEST_ASSERT(devRec->PnpState == WdfDevStatePnpStarted, "Device PnP state must be WdfDevStatePnpStarted");
    TEST_ASSERT(devRec->PowerState == WdfDevStatePowerD0, "Device Power state must be WdfDevStatePowerD0");

    // Stage 4: Sequential Queue Dispatching & Automatic Serialization
    WDF_IO_QUEUE_CONFIG seqCfg{};
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&seqCfg, WdfIoQueueDispatchSequential);
    seqCfg.EvtIoWrite = [](WDFQUEUE, WDFREQUEST, size_t) {};

    WDFQUEUE hSeqQueue = nullptr;
    status = WdfIoQueueCreate(hDevice, &seqCfg, nullptr, &hSeqQueue);
    TEST_ASSERT(NT_SUCCESS(status) && hSeqQueue != nullptr, "Sequential WdfIoQueueCreate must succeed");

    WDFREQUEST hReq1 = nullptr;
    WDFREQUEST hReq2 = nullptr;
    WdfRequestCreate(nullptr, nullptr, &hReq1);
    WdfRequestCreate(nullptr, nullptr, &hReq2);

    auto* r1 = reinterpret_cast<WdfRequestRecord*>(hReq1);
    auto* r2 = reinterpret_cast<WdfRequestRecord*>(hReq2);
    r1->Type = WdfRequestTypeWrite;
    r1->InputBuffer = {10, 20, 30};
    r2->Type = WdfRequestTypeWrite;
    r2->InputBuffer = {40, 50, 60};

    // Dispatch Req1
    engine.dispatchRequest(hSeqQueue, hReq1);
    auto* qRec = reinterpret_cast<WdfQueueRecord*>(hSeqQueue);
    TEST_ASSERT(qRec->InFlightRequests.size() == 1, "Sequential queue must have 1 in-flight request");
    TEST_ASSERT(qRec->PendingRequests.empty(), "Sequential queue must have 0 pending requests");

    // Dispatch Req2 while Req1 is still in-flight
    engine.dispatchRequest(hSeqQueue, hReq2);
    TEST_ASSERT(qRec->InFlightRequests.size() == 1, "Sequential queue must still have only 1 in-flight request");
    TEST_ASSERT(qRec->PendingRequests.size() == 1, "Sequential queue must hold Req2 as pending");

    // Complete Req1
    WdfRequestCompleteWithInformation(hReq1, STATUS_SUCCESS, 3);
    TEST_ASSERT(r1->IsCompleted, "Req1 must be marked completed");
    // After Req1 completes, Req2 must be automatically dispatched!
    TEST_ASSERT(qRec->InFlightRequests.size() == 1, "Req2 must have been promoted to in-flight");
    TEST_ASSERT(qRec->InFlightRequests[0] == r2, "In-flight request must now be Req2");
    TEST_ASSERT(qRec->PendingRequests.empty(), "Pending queue must now be empty");

    // Complete Req2
    WdfRequestCompleteWithInformation(hReq2, STATUS_SUCCESS, 3);
    TEST_ASSERT(r2->IsCompleted, "Req2 must be marked completed");
    TEST_ASSERT(qRec->InFlightRequests.empty(), "Queue must have 0 in-flight requests after all complete");

    // Stage 5: Parallel Queue Dispatching
    WDF_IO_QUEUE_CONFIG parCfg{};
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&parCfg, WdfIoQueueDispatchParallel);
    WDFQUEUE hParQueue = nullptr;
    status = WdfIoQueueCreate(hDevice, &parCfg, nullptr, &hParQueue);
    TEST_ASSERT(NT_SUCCESS(status) && hParQueue != nullptr, "Parallel WdfIoQueueCreate must succeed");

    WDFREQUEST hPReq1 = nullptr;
    WDFREQUEST hPReq2 = nullptr;
    WdfRequestCreate(nullptr, nullptr, &hPReq1);
    WdfRequestCreate(nullptr, nullptr, &hPReq2);

    engine.dispatchRequest(hParQueue, hPReq1);
    engine.dispatchRequest(hParQueue, hPReq2);

    auto* parRec = reinterpret_cast<WdfQueueRecord*>(hParQueue);
    TEST_ASSERT(parRec->InFlightRequests.size() == 2, "Parallel queue must allow both requests in flight simultaneously");

    WdfRequestComplete(hPReq1, STATUS_SUCCESS);
    WdfRequestComplete(hPReq2, STATUS_SUCCESS);
    TEST_ASSERT(parRec->InFlightRequests.empty(), "Parallel queue in-flight cleared after completions");

    // Stage 6: Manual Queue Dispatching
    WDF_IO_QUEUE_CONFIG manCfg{};
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&manCfg, WdfIoQueueDispatchManual);
    WDFQUEUE hManQueue = nullptr;
    status = WdfIoQueueCreate(hDevice, &manCfg, nullptr, &hManQueue);
    TEST_ASSERT(NT_SUCCESS(status) && hManQueue != nullptr, "Manual WdfIoQueueCreate must succeed");

    WDFREQUEST hMReq = nullptr;
    WdfRequestCreate(nullptr, nullptr, &hMReq);
    engine.dispatchRequest(hManQueue, hMReq);

    auto* manRec = reinterpret_cast<WdfQueueRecord*>(hManQueue);
    TEST_ASSERT(manRec->PendingRequests.size() == 1, "Manual queue must hold request in pending queue");
    TEST_ASSERT(manRec->InFlightRequests.empty(), "Manual queue must not auto-dispatch requests");

    WDFREQUEST hRetrievedReq = nullptr;
    status = WdfIoQueueRetrieveNextRequest(hManQueue, &hRetrievedReq);
    TEST_ASSERT(NT_SUCCESS(status) && hRetrievedReq == hMReq, "WdfIoQueueRetrieveNextRequest must retrieve the queued request");
    WdfRequestComplete(hRetrievedReq, STATUS_SUCCESS);

    // Stage 7: Buffer Extraction & Verification
    WDFREQUEST hBufReq = nullptr;
    WdfRequestCreate(nullptr, nullptr, &hBufReq);
    auto* bufRec = reinterpret_cast<WdfRequestRecord*>(hBufReq);
    bufRec->InputBuffer = {'H', 'E', 'L', 'L', 'O'};
    bufRec->OutputBuffer.resize(16, 0);

    void* inBuf = nullptr;
    size_t inLen = 0;
    status = WdfRequestRetrieveInputBuffer(hBufReq, 5, &inBuf, &inLen);
    TEST_ASSERT(NT_SUCCESS(status) && inBuf != nullptr && inLen == 5, "WdfRequestRetrieveInputBuffer must succeed");
    TEST_ASSERT(std::memcmp(inBuf, "HELLO", 5) == 0, "Input buffer content match");

    void* outBuf = nullptr;
    size_t outLen = 0;
    status = WdfRequestRetrieveOutputBuffer(hBufReq, 16, &outBuf, &outLen);
    TEST_ASSERT(NT_SUCCESS(status) && outBuf != nullptr && outLen == 16, "WdfRequestRetrieveOutputBuffer must succeed");
    WdfRequestCompleteWithInformation(hBufReq, STATUS_SUCCESS, 5);

    // Stage 8: Power State Transitions
    status = WdfDeviceSetPowerState(hDevice, WdfDevStatePowerD3);
    TEST_ASSERT(NT_SUCCESS(status), "Transition to D3 must succeed");
    TEST_ASSERT(d0ExitCalled, "EvtDeviceD0Exit callback must be triggered on D3 transition");
    TEST_ASSERT(devRec->PowerState == WdfDevStatePowerD3, "PowerState must be D3");

    d0EntryCalled = false;
    status = WdfDeviceSetPowerState(hDevice, WdfDevStatePowerD0);
    TEST_ASSERT(NT_SUCCESS(status), "Transition to D0 must succeed");
    TEST_ASSERT(d0EntryCalled, "EvtDeviceD0Entry callback must be triggered on D0 resume");
    TEST_ASSERT(devRec->PowerState == WdfDevStatePowerD0, "PowerState must be restored to D0");

    // Stage 9: Memory Object Allocation
    WDFMEMORY hMem = nullptr;
    void* memPtr = nullptr;
    status = WdfMemoryCreate(nullptr, 0, 0x4D447672 /* 'MDvr' */, 256, &hMem, &memPtr);
    TEST_ASSERT(NT_SUCCESS(status) && hMem != nullptr && memPtr != nullptr, "WdfMemoryCreate must succeed");
    std::memset(memPtr, 0xAA, 256);
    TEST_ASSERT(static_cast<uint8_t*>(memPtr)[128] == 0xAA, "Memory write/read verified");

    // Stage 10: UMDF 2.0 User-Mode Driver Host & Fault Containment
    uint32_t umdfPid = 0;
    status = engine.startUmdfDriver("sensors.hid.dll", &umdfPid);
    TEST_ASSERT(NT_SUCCESS(status) && umdfPid > 0, "UMDF Host startup must succeed");

    status = engine.simulateUmdfCrash(umdfPid, true);
    TEST_ASSERT(NT_SUCCESS(status), "UMDF crash containment and reflector recovery must succeed without kernel panic");
    auto hosts = engine.getUmdfHostsSnapshot();
    TEST_ASSERT(hosts[umdfPid].CrashesRecovered == 1, "UMDF host recovery counter must increment");

    // Stage 11: Cascading Deletion
    bool cleanupCalled = false;
    WDF_OBJECT_ATTRIBUTES childAttr{};
    WDF_OBJECT_ATTRIBUTES_INIT(&childAttr);
    childAttr.ParentObject = hDevice;
    childAttr.EvtCleanupCallback = [&](WDFOBJECT) {
        cleanupCalled = true;
    };
    WDFREQUEST hChildReq = nullptr;
    WdfRequestCreate(&childAttr, nullptr, &hChildReq);

    WdfObjectDelete(hDevice);
    TEST_ASSERT(cleanupCalled, "Deleting parent device must automatically cascade and cleanup child objects");

    std::cout << "[TEST] Suite 149: Windows Driver Frameworks (KMDF & UMDF 2.0) Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Windows Driver Frameworks (KMDF v1.33 & UMDF 2.0) Core Library\n";
    std::cout << "       Codename: TitanWDF / AegisWDF | Binary: Wdf01000.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_WindowsDriverFrameworks_WDF_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
