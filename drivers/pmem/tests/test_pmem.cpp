// ============================================================================
// Standalone Driver Verification Test: pmem (TitanPMEM / NexusPMEM)
// Subsystem: Persistent Memory (NVDIMM / Optane PMEM) & DAX Storage Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/pmem.hpp"

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

void Test_PersistentMemory_NVDIMM_Optane_DAX_Subsystem() {
    std::cout << "[TEST] Starting Suite 165: Persistent Memory (NVDIMM / Intel Optane PMEM) & DAX Storage Subsystem...\n";

    // Stage 1: Subsystem Initialization & Version Check
    pmem::InitializePmemSubsystem();
    auto& pmemSub = pmem::TitanPmemSubsystem::Instance();
    TEST_ASSERT(pmemSub.isInitialized(), "PMEM subsystem must be initialized");
    uint32_t ver = pmem::PmemGetVersion();
    TEST_ASSERT(ver == 0x00010000, "PMEM driver version must be 1.0 (0x00010000)");

    // Stage 2: Physical NVDIMM Module Enumeration (Intel Optane PMEM 300 Series)
    uint32_t devCount = pmem::PmemGetDeviceCount();
    TEST_ASSERT(devCount == 2, "Must enumerate 2 physical Optane PMEM modules");
    pmem::PmemNvdimmDevice dev1{};
    NTSTATUS dev1St = pmem::PmemGetDeviceInfo(1, &dev1);
    TEST_ASSERT(dev1St == STATUS_SUCCESS, "Retrieving device 1 info must succeed");
    TEST_ASSERT(dev1.modelNumber.find("Optane") != std::string::npos, "Device 1 must be an Intel Optane PMEM module");
    TEST_ASSERT(dev1.capacityBytes == 512ULL * 1024ULL * 1024ULL * 1024ULL, "Device 1 must have 512 GB capacity");
    TEST_ASSERT(dev1.health == pmem::PmemHealthStatus::Healthy, "Device 1 health status must be Healthy");
    TEST_ASSERT(dev1.adrBatteryBacked, "Device 1 must support Asynchronous DRAM Refresh (ADR) battery backup");

    pmem::PmemNvdimmDevice dev2{};
    NTSTATUS dev2St = pmem::PmemGetDeviceInfo(2, &dev2);
    TEST_ASSERT(dev2St == STATUS_SUCCESS, "Retrieving device 2 info must succeed");
    TEST_ASSERT(dev2.capacityBytes == 512ULL * 1024ULL * 1024ULL * 1024ULL, "Device 2 must have 512 GB capacity");

    // Stage 3: Logical PMEM Pool Discovery (App Direct & BTT)
    uint32_t poolCount = pmem::PmemGetPoolCount();
    TEST_ASSERT(poolCount == 2, "Must discover 2 logical PMEM pools");
    pmem::PmemPool pool1{};
    NTSTATUS pool1St = pmem::PmemGetPoolInfo(1, &pool1);
    TEST_ASSERT(pool1St == STATUS_SUCCESS, "Retrieving pool 1 info must succeed");
    TEST_ASSERT(pool1.mode == pmem::PmemOperatingMode::AppDirect_DAX, "Pool 1 must be configured for App Direct DAX mode");
    TEST_ASSERT(pool1.totalCapacityBytes == 1024ULL * 1024ULL * 1024ULL * 1024ULL, "Pool 1 capacity must be 1 TB");
    TEST_ASSERT(pool1.interleaveWays == 2, "Pool 1 must be 2-way interleaved across modules");
    TEST_ASSERT(pool1.interleaveLineSize == 256, "Pool 1 interleave line size must be 256 bytes");

    pmem::PmemPool pool2{};
    NTSTATUS pool2St = pmem::PmemGetPoolInfo(2, &pool2);
    TEST_ASSERT(pool2St == STATUS_SUCCESS, "Retrieving pool 2 info must succeed");
    TEST_ASSERT(pool2.mode == pmem::PmemOperatingMode::Sector_BTT, "Pool 2 must be configured for Block Translation Table mode");
    TEST_ASSERT(pool2.totalCapacityBytes == 128ULL * 1024ULL * 1024ULL * 1024ULL, "Pool 2 capacity must be 128 GB");

    // Stage 4: App Direct DAX Userland Memory Mapping Allocation
    uint64_t mapId = 0;
    uint64_t virtAddr = 0;
    NTSTATUS mapSt = pmem::DaxMapFileToMemory("C:\\Data\\HighFrequencyOrderBook.dat", 64ULL * 1024ULL * 1024ULL, 1, &mapId, &virtAddr);
    TEST_ASSERT(mapSt == STATUS_SUCCESS, "DaxMapFileToMemory must succeed");
    TEST_ASSERT(mapId >= 5001, "Valid DAX mapping ID must be allocated");

    // Stage 5: Zero-Copy Virtual Address Window Assignment
    TEST_ASSERT(virtAddr == 0x7FFF00000000ULL, "DAX virtual address must be mapped into the 64-bit userland DAX window");
    auto activeMappings = pmemSub.getActiveDaxMappings();
    TEST_ASSERT(!activeMappings.empty(), "Active DAX mappings list must contain the new mapping");

    // Stage 6: Cache Line Write-Back & Persistence Barrier Flush (clwb + sfence)
    uint32_t flushLatNs = 0;
    NTSTATUS flushSt = pmem::PmemFlushCacheLine(mapId, 0, 64, &flushLatNs);
    TEST_ASSERT(flushSt == STATUS_SUCCESS, "PmemFlushCacheLine must succeed for a 64-byte cache line");

    // Stage 7: Sub-100 Nanosecond Persistence Flush Latency Verification
    TEST_ASSERT(flushLatNs < 100, "Persistence flush latency must be sub-100 nanoseconds (< 100ns)");

    // Stage 8: Read, Write & Flush Latency Verification
    pmem::PmemTelemetry telem{};
    NTSTATUS telemSt = pmem::PmemGetTelemetry(&telem);
    TEST_ASSERT(telemSt == STATUS_SUCCESS, "Telemetry query must succeed");
    TEST_ASSERT(telem.avgReadLatencyNs < 300, "App Direct read latency must be sub-300ns (~210ns)");
    TEST_ASSERT(telem.avgWriteLatencyNs < 250, "App Direct write latency must be sub-250ns (~180ns)");
    TEST_ASSERT(telem.avgFlushLatencyNs < 100, "Hardware flush barrier latency must be sub-100ns (~85ns)");

    // Stage 9: Block Translation Table (BTT) Atomic 4KB Sector Update
    uint64_t prevWritten = telem.totalBytesWritten;
    uint64_t prevFlushes = telem.totalCacheLineFlushes;
    uint8_t dummySector[4096]{};
    dummySector[0] = 0xAA;
    dummySector[4095] = 0x55;
    bool bttOk = pmemSub.writeBttAtomicSector(2, 100, dummySector);
    TEST_ASSERT(bttOk, "BTT atomic sector write must succeed on Pool 2");
    pmem::PmemGetTelemetry(&telem);
    TEST_ASSERT(telem.totalBytesWritten == prevWritten + 4096, "BTT write must update written telemetry by 4096 bytes");
    TEST_ASSERT(telem.totalCacheLineFlushes == prevFlushes + 64, "BTT 4KB atomic sector write must flush 64 cache lines");

    // Stage 10: Asynchronous DRAM Refresh (ADR) Power Protection Circuit Status
    TEST_ASSERT(telem.adrProtectionArmActive, "Asynchronous DRAM Refresh (ADR) circuit must be armed and active");

    // Stage 11: DAX Unmap Operation & Capacity Reclamation
    uint64_t beforeAlloc = pmemSub.getPool(1)->allocatedBytes;
    NTSTATUS unmapSt = pmem::DaxUnmapFile(mapId);
    TEST_ASSERT(unmapSt == STATUS_SUCCESS, "DaxUnmapFile must successfully release the DAX mapping");
    uint64_t afterAlloc = pmemSub.getPool(1)->allocatedBytes;
    TEST_ASSERT(afterAlloc < beforeAlloc, "Pool allocated bytes must be reclaimed upon unmapping");

    // Stage 12: Rejection of Out-of-Bounds Cache Line Flush
    uint32_t badLat = 0;
    NTSTATUS badFlushSt = pmem::PmemFlushCacheLine(mapId, 0x10000000, 64, &badLat);
    TEST_ASSERT(badFlushSt != STATUS_SUCCESS, "Out-of-bounds or invalid mapping flush must be rejected");

    // Stage 13: ACPI NFIT Range Descriptor Validation
    TEST_ASSERT(pmem::ACPI_NFIT_SIGNATURE == 0x5449464E, "ACPI NFIT signature must match 'NFIT'");
    TEST_ASSERT(pmem::SEC_DAX == 0x02000000, "SEC_DAX allocation flag must match Win32 specification (0x02000000)");
    TEST_ASSERT(pmem::GUID_PMEM_BYTE_ADDRESSABLE.data1 == 0x7305944f, "App Direct byte-addressable GUID data1 must match standard");
    TEST_ASSERT(pmem::GUID_PMEM_BLOCK_TRANSLATION_TABLE.data1 == 0x1928cdab, "BTT sector GUID data1 must match standard");

    // Stage 14: Driver C ABI Exports Verification (pmem.sys & dax.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemInitialize") != nullptr, "PmemInitialize export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetVersion") != nullptr, "PmemGetVersion export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetDeviceCount") != nullptr, "PmemGetDeviceCount export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetDeviceInfo") != nullptr, "PmemGetDeviceInfo export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetPoolCount") != nullptr, "PmemGetPoolCount export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetPoolInfo") != nullptr, "PmemGetPoolInfo export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemFlushCacheLine") != nullptr, "PmemFlushCacheLine export must exist");
    TEST_ASSERT(ldr.getExport("pmem.sys", "PmemGetTelemetry") != nullptr, "PmemGetTelemetry export must exist");
    TEST_ASSERT(ldr.getExport("dax.sys", "DaxMapFileToMemory") != nullptr, "DaxMapFileToMemory export must exist");
    TEST_ASSERT(ldr.getExport("dax.sys", "DaxUnmapFile") != nullptr, "DaxUnmapFile export must exist");

    // Stage 15: SCM Driver Service Registrations (pmem.sys & dax.sys)
    auto pmemSvc = scm::ServiceControlManager::get().getServiceRecord(L"pmem");
    TEST_ASSERT(pmemSvc != nullptr, "pmem service record must exist in SCM");
    TEST_ASSERT(pmemSvc->startType == scm::SERVICE_BOOT_START, "pmem must be configured with SERVICE_BOOT_START");

    auto daxSvc = scm::ServiceControlManager::get().getServiceRecord(L"dax");
    TEST_ASSERT(daxSvc != nullptr, "dax service record must exist in SCM");
    TEST_ASSERT(daxSvc->startType == scm::SERVICE_SYSTEM_START, "dax must be configured with SERVICE_SYSTEM_START");

    // Stage 16: Version Database Registration Verification
    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("pmem.sys") != nullptr, "pmem.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("dax.sys") != nullptr, "dax.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 165: Persistent Memory (NVDIMM / Intel Optane PMEM) & DAX Storage Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Persistent Memory (NVDIMM / Optane PMEM) & DAX Storage Subsystem\n";
    std::cout << "       Codename: TitanPMEM / NexusPMEM | Binary: pmem.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_PersistentMemory_NVDIMM_Optane_DAX_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
