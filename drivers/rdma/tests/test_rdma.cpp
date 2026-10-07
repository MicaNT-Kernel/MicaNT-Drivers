// ============================================================================
// Standalone Driver Verification Test: rdma (TitanRDMA / NexusSMB)
// Subsystem: Remote Direct Memory Access (RoCE v2 / InfiniBand) & SMB Direct
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/rdma.hpp"

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

void Test_RDMA_RoCEv2_InfiniBand_SMBDirect_Subsystem() {
    std::cout << "[TEST] Starting Suite 166: Remote Direct Memory Access (RDMA / RoCE v2 & InfiniBand) & SMB Direct Subsystem...\n";

    // Stage 1: Subsystem Initialization & Version Check
    rdma::InitializeRdmaSubsystem();
    auto& rdmaSub = rdma::TitanRdmaSubsystem::Instance();
    TEST_ASSERT(rdmaSub.isInitialized(), "RDMA subsystem must be initialized");
    uint32_t ver = rdma::RdmaGetVersion();
    TEST_ASSERT(ver == 0x00010000, "RDMA version must be 1.0 (0x00010000)");

    // Stage 2: Hardware Host Channel Adapter (HCA) Discovery
    TEST_ASSERT(rdmaSub.getAdapterName().find("RazzleNet-RDMA") != std::string::npos, "HCA adapter name must match RazzleNet-RDMA");
    TEST_ASSERT(rdmaSub.getPcieLocation() == "00:0A.0", "HCA PCIe location must be 00:0A.0");
    TEST_ASSERT(rdmaSub.getTransport() == rdma::RdmaTransportType::RoCE_v2, "Transport technology must default to RoCE v2");
    TEST_ASSERT(rdmaSub.getLinkSpeedBps() == 100ULL * 1000ULL * 1000ULL * 1000ULL, "Link speed must be 100 Gbps");

    // Stage 3: Protection Domain (PD) Allocation
    uint32_t pdId = 0;
    NTSTATUS pdSt = rdma::RdmaCreateProtectionDomain(&pdId);
    TEST_ASSERT(pdSt == STATUS_SUCCESS, "RdmaCreateProtectionDomain must succeed");
    TEST_ASSERT(pdId >= 101, "Allocated Protection Domain ID must be valid");

    // Stage 4: Completion Queue (CQ) Creation (Send CQ & Recv CQ)
    uint32_t sendCqId = 0;
    uint32_t recvCqId = 0;
    NTSTATUS scqSt = rdma::RdmaCreateCompletionQueue(1024, &sendCqId);
    NTSTATUS rcqSt = rdma::RdmaCreateCompletionQueue(1024, &recvCqId);
    TEST_ASSERT(scqSt == STATUS_SUCCESS, "Creating Send CQ must succeed");
    TEST_ASSERT(rcqSt == STATUS_SUCCESS, "Creating Recv CQ must succeed");
    TEST_ASSERT(sendCqId > 0 && recvCqId > 0, "Valid CQ IDs must be allocated");

    // Stage 5: Reliable Connected Queue Pair (QP) Allocation
    uint32_t qpId = 0;
    NTSTATUS qpSt = rdma::RdmaCreateQueuePair(pdId, static_cast<uint32_t>(rdma::QueuePairType::ReliableConnected),
                                             sendCqId, recvCqId, 512, 512, &qpId);
    TEST_ASSERT(qpSt == STATUS_SUCCESS, "RdmaCreateQueuePair must succeed");
    TEST_ASSERT(qpId >= 401, "Allocated Queue Pair ID must be valid");
    const auto* qp = rdmaSub.getQueuePair(qpId);
    TEST_ASSERT(qp != nullptr, "Retrieved Queue Pair pointer must not be null");
    TEST_ASSERT(qp->state == rdma::QueuePairState::Init, "New QP must start in Init state");

    // Stage 6: Queue Pair State Machine Transition to RTS (Ready to Send)
    bool modOk = rdmaSub.modifyQueuePair(qpId, rdma::QueuePairState::RTS, 5001, "192.168.10.88", rdma::ROCE_V2_UDP_PORT, 0x400000);
    TEST_ASSERT(modOk, "Modifying Queue Pair state must succeed");
    qp = rdmaSub.getQueuePair(qpId);
    TEST_ASSERT(qp->state == rdma::QueuePairState::RTS, "QP state must now be RTS");
    TEST_ASSERT(qp->remoteQpId == 5001, "Remote QP ID must match");
    TEST_ASSERT(qp->remotePort == rdma::ROCE_V2_UDP_PORT, "Remote port must match RoCE v2 UDP port (4791)");

    // Stage 7: Zero-Copy Memory Region (MR) Registration
    uint32_t mrId = 0;
    uint32_t lkey = 0;
    uint32_t rkey = 0;
    NTSTATUS mrSt = rdma::RdmaRegisterMemoryRegion(pdId, 0x600010000000ULL, 16ULL * 1024ULL * 1024ULL,
                                                  rdma::RDMA_ACCESS_LOCAL_READ | rdma::RDMA_ACCESS_LOCAL_WRITE |
                                                  rdma::RDMA_ACCESS_REMOTE_READ | rdma::RDMA_ACCESS_REMOTE_WRITE,
                                                  &mrId, &lkey, &rkey);
    TEST_ASSERT(mrSt == STATUS_SUCCESS, "RdmaRegisterMemoryRegion must succeed");
    TEST_ASSERT(mrId >= 201, "Allocated MR ID must be valid");
    TEST_ASSERT(lkey != 0 && rkey != 0, "Valid lkey and rkey must be generated");

    // Stage 8: Post Receive Work Request Submission
    NTSTATUS recvSt = rdma::RdmaPostReceive(qpId, 1001, 4096);
    TEST_ASSERT(recvSt == STATUS_SUCCESS, "RdmaPostReceive must succeed on RTS/RTR queue pair");

    // Stage 9: Remote Direct Memory Access Write (RDMA Write) Execution
    uint32_t writeLatNs = 0;
    NTSTATUS writeSt = rdma::RdmaPostSend(qpId, 2001, static_cast<uint32_t>(rdma::RdmaWorkOp::RdmaWrite),
                                         65536, 0x600010000000ULL, rkey, &writeLatNs);
    TEST_ASSERT(writeSt == STATUS_SUCCESS, "RdmaPostSend with RdmaWrite must succeed");
    TEST_ASSERT(writeLatNs < 3000, "RDMA write latency must be sub-3.0 microseconds (< 3000 ns)");

    // Stage 10: Remote Direct Memory Access Read (RDMA Read) Execution
    uint32_t readLatNs = 0;
    NTSTATUS readSt = rdma::RdmaPostSend(qpId, 2002, static_cast<uint32_t>(rdma::RdmaWorkOp::RdmaRead),
                                        65536, 0x600010000000ULL, rkey, &readLatNs);
    TEST_ASSERT(readSt == STATUS_SUCCESS, "RdmaPostSend with RdmaRead must succeed");
    TEST_ASSERT(readLatNs < 3500, "RDMA read latency must be sub-3.5 microseconds (< 3500 ns)");

    // Stage 11: Hardware Completion Queue (CQ) Polling
    rdma::RdmaWorkCompletion completions[8]{};
    uint32_t completedCount = 0;
    NTSTATUS pollSt = rdma::RdmaPollCq(sendCqId, 8, completions, &completedCount);
    TEST_ASSERT(pollSt == STATUS_SUCCESS, "RdmaPollCq must succeed");
    TEST_ASSERT(completedCount == 2, "Must retrieve exactly 2 completed operations (Write and Read)");
    TEST_ASSERT(completions[0].status == rdma::RdmaCompletionStatus::Success, "Completion 1 status must be Success");
    TEST_ASSERT(completions[1].status == rdma::RdmaCompletionStatus::Success, "Completion 2 status must be Success");

    // Stage 12: SMB Direct Storage Acceleration Session Connection
    uint32_t smbSessId = 0;
    uint32_t smbQp = 0;
    NTSTATUS smbConnSt = rdma::SmbDirectConnect("\\\\TitanStorageCluster\\FastVHDX", &smbSessId, &smbQp);
    TEST_ASSERT(smbConnSt == STATUS_SUCCESS, "SmbDirectConnect must succeed");
    TEST_ASSERT(smbSessId >= 501, "Allocated SMB Direct session ID must be valid");
    const auto* smbSess = rdmaSub.getSmbSession(smbSessId);
    TEST_ASSERT(smbSess != nullptr && smbSess->isConnected, "SMB Direct session must be active and connected");
    TEST_ASSERT(smbSess->sendCreditsAvailable > 0, "SMB Direct send credits must be granted");

    // Stage 13: SMB Direct Remote High-Speed Write & Read Operations
    uint32_t smbWriteLat = 0;
    NTSTATUS smbWSt = rdma::SmbDirectRemoteWrite(smbSessId, 0, 1048576, &smbWriteLat);
    TEST_ASSERT(smbWSt == STATUS_SUCCESS, "SmbDirectRemoteWrite of 1MB segment must succeed");
    TEST_ASSERT(smbWriteLat < 3000, "SMB Direct write latency must be sub-3.0 microseconds");

    uint32_t smbReadLat = 0;
    NTSTATUS smbRSt = rdma::SmbDirectRemoteRead(smbSessId, 0, 1048576, &smbReadLat);
    TEST_ASSERT(smbRSt == STATUS_SUCCESS, "SmbDirectRemoteRead of 1MB segment must succeed");
    TEST_ASSERT(smbReadLat < 3500, "SMB Direct read latency must be sub-3.5 microseconds");

    // Stage 14: Wire-Speed Telemetry & Resilient Lossless Recovery
    rdma::RdmaTelemetry telem{};
    NTSTATUS telemSt = rdma::RdmaGetTelemetry(&telem);
    TEST_ASSERT(telemSt == STATUS_SUCCESS, "RdmaGetTelemetry must succeed");
    TEST_ASSERT(telem.sustainedBandwidthMBps > 10000, "Sustained line bandwidth must exceed 10,000 MB/s (> 80 Gbps)");
    TEST_ASSERT(telem.losslessFabricActive, "TitanRoCE autonomous lossless fabric recovery must be active");
    TEST_ASSERT(telem.pfcEnabled, "Priority Flow Control (PFC) must be enabled");
    TEST_ASSERT(telem.ecnEnabled, "Explicit Congestion Notification (ECN) must be enabled");

    // Stage 15: Driver C ABI Exports Verification (ndisrdma.sys & smbdirect.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaInitialize") != nullptr, "RdmaInitialize export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaGetVersion") != nullptr, "RdmaGetVersion export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaCreateProtectionDomain") != nullptr, "RdmaCreateProtectionDomain export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaCreateCompletionQueue") != nullptr, "RdmaCreateCompletionQueue export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaCreateQueuePair") != nullptr, "RdmaCreateQueuePair export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaRegisterMemoryRegion") != nullptr, "RdmaRegisterMemoryRegion export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaPostSend") != nullptr, "RdmaPostSend export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaPostReceive") != nullptr, "RdmaPostReceive export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaPollCq") != nullptr, "RdmaPollCq export must exist");
    TEST_ASSERT(ldr.getExport("ndisrdma.sys", "RdmaGetTelemetry") != nullptr, "RdmaGetTelemetry export must exist");
    TEST_ASSERT(ldr.getExport("smbdirect.sys", "SmbDirectInitialize") != nullptr, "SmbDirectInitialize export must exist");
    TEST_ASSERT(ldr.getExport("smbdirect.sys", "SmbDirectConnect") != nullptr, "SmbDirectConnect export must exist");
    TEST_ASSERT(ldr.getExport("smbdirect.sys", "SmbDirectDisconnect") != nullptr, "SmbDirectDisconnect export must exist");
    TEST_ASSERT(ldr.getExport("smbdirect.sys", "SmbDirectRemoteWrite") != nullptr, "SmbDirectRemoteWrite export must exist");
    TEST_ASSERT(ldr.getExport("smbdirect.sys", "SmbDirectRemoteRead") != nullptr, "SmbDirectRemoteRead export must exist");

    // Stage 16: SCM Driver Service & Version Database Registration
    auto rdmaSvc = scm::ServiceControlManager::get().getServiceRecord(L"ndisrdma");
    TEST_ASSERT(rdmaSvc != nullptr, "ndisrdma service record must exist in SCM");
    TEST_ASSERT(rdmaSvc->startType == scm::SERVICE_BOOT_START, "ndisrdma must have SERVICE_BOOT_START");

    auto smbdSvc = scm::ServiceControlManager::get().getServiceRecord(L"smbdirect");
    TEST_ASSERT(smbdSvc != nullptr, "smbdirect service record must exist in SCM");
    TEST_ASSERT(smbdSvc->startType == scm::SERVICE_SYSTEM_START, "smbdirect must have SERVICE_SYSTEM_START");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("ndisrdma.sys") != nullptr, "ndisrdma.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("smbdirect.sys") != nullptr, "smbdirect.sys must be registered in Version Database");

    // Cleanup resources
    rdmaSub.smbDirectDisconnect(smbSessId);
    rdmaSub.deregisterMemoryRegion(mrId);
    rdmaSub.destroyQueuePair(qpId);
    rdmaSub.destroyCompletionQueue(sendCqId);
    rdmaSub.destroyCompletionQueue(recvCqId);
    rdmaSub.destroyProtectionDomain(pdId);

    std::cout << "[TEST] Suite 166: Remote Direct Memory Access (RDMA / RoCE v2 & InfiniBand) & SMB Direct Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Remote Direct Memory Access (RoCE v2 / InfiniBand) & SMB Direct\n";
    std::cout << "       Codename: TitanRDMA / NexusSMB | Binary: ndisrdma.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_RDMA_RoCEv2_InfiniBand_SMBDirect_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
