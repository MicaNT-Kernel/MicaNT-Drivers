// ============================================================================
// MicaNT: DaytonaMM - Sovereign Clean-Room Memory Management Subsystem
// 
// Named in tribute to Windows NT 3.5 "Daytona" (1994), celebrated for
// radically slashing NT's memory footprint, eliminating memory leaks, and
// stabilizing the Virtual Memory Manager (VMM).
//
// Strict Clean-Room Implementation in modern ISO C++23.
// Zero proprietary code or leaked markers. References open Win32 metadata.
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "mm.hpp"
#include "heap.hpp"
#include "lookaside.hpp"
#include <cstdint>
#include <vector>
#include <deque>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <algorithm>
#include <chrono>

namespace micant::daytonamm {

using namespace micant::mm;

// ============================================================================
// 1. Daytona PFN (Page Frame Number) Database & State Transitions
// ============================================================================

enum class PfnState : uint8_t {
    Free = 0,       // Available for allocation, contains indeterminate data
    Zeroed,         // Cleared to zero by background thread, ready for demand-zero
    Active,         // Currently mapped into a process or kernel address space
    Standby,        // Clean page evicted from working set; can be reclaimed instantly
    Modified,       // Dirty page evicted from working set; requires flushing
    Bad             // Hardware memory fault detected
};

struct PfnEntry {
    uint64_t pfn{0};                // Physical Page Frame Number
    PfnState state{PfnState::Free}; // Current page lifecycle state
    uint64_t referenceCount{0};     // Number of PTEs referencing this PFN
    uintptr_t virtualAddress{0};    // Owning process virtual address
    uint32_t processId{0};          // Owning process ID (0 = Kernel)
    bool modified{false};           // Dirty flag
    uint64_t lastAccessTick{0};     // LRU timestamp for working set trimming
};

// ============================================================================
// 2. Daytona Memory Telemetry
// ============================================================================

struct DaytonaTelemetry {
    size_t totalPhysicalPages{0};
    size_t freePages{0};
    size_t zeroedPages{0};
    size_t activePages{0};
    size_t standbyPages{0};
    size_t modifiedPages{0};
    size_t badPages{0};
    
    // Paging telemetry
    uint64_t pageFaultCount{0};
    uint64_t demandZeroFaults{0};
    uint64_t transitionFaults{0};
    uint64_t workingSetTrims{0};
    uint64_t pagesEvicted{0};

    // Commit charge in bytes
    size_t currentCommitBytes{0};
    size_t peakCommitBytes{0};
};

// ============================================================================
// 3. Process Working Set Tracker
// ============================================================================

struct WorkingSetEntry {
    uintptr_t virtualAddress{0};
    uint64_t pfn{0};
    uint32_t protection{PAGE_READWRITE};
    uint64_t touchTick{0};
    bool valid{true};
};

class ProcessWorkingSet {
public:
    explicit ProcessWorkingSet(size_t maxWorkingSetPages = 256)
        : m_maxPages(maxWorkingSetPages) {}

    void insertPage(uintptr_t vaddr, uint64_t pfn, uint32_t protect, uint64_t tick) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_entries[vaddr] = { vaddr, pfn, protect, tick, true };
    }

    bool removePage(uintptr_t vaddr, WorkingSetEntry& outEntry) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_entries.find(vaddr);
        if (it != m_entries.end()) {
            outEntry = it->second;
            m_entries.erase(it);
            return true;
        }
        return false;
    }

    [[nodiscard]] size_t getResidentPageCount() const noexcept {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_entries.size();
    }

    [[nodiscard]] size_t getMaxPages() const noexcept { return m_maxPages; }

    /**
     * @brief Identifies least recently used pages for working set trimming.
     */
    std::vector<WorkingSetEntry> selectPagesToTrim(size_t targetCount) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<WorkingSetEntry> candidates;
        for (const auto& [addr, entry] : m_entries) {
            candidates.push_back(entry);
        }

        // Sort by touchTick ascending (oldest first)
        std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
            return a.touchTick < b.touchTick;
        });

        if (candidates.size() > targetCount) {
            candidates.resize(targetCount);
        }

        for (const auto& c : candidates) {
            m_entries.erase(c.virtualAddress);
        }
        return candidates;
    }

private:
    mutable std::mutex m_mutex;
    size_t m_maxPages{256};
    std::unordered_map<uintptr_t, WorkingSetEntry> m_entries;
};

// ============================================================================
// 4. DaytonaMemoryExecutive - Core Daytona VMM Subsystem
// ============================================================================

class DaytonaMemoryExecutive {
public:
    static DaytonaMemoryExecutive& get() {
        static DaytonaMemoryExecutive instance;
        return instance;
    }

    /**
     * @brief Initializes the physical PFN database and page pools.
     */
    void initialize(size_t totalMemoryPages = 8192) { // Default 32MB (8192 * 4KB)
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        m_pfnDatabase.resize(totalMemoryPages);
        m_freeList.clear();
        m_zeroedList.clear();
        m_standbyList.clear();
        m_modifiedList.clear();

        for (size_t i = 0; i < totalMemoryPages; ++i) {
            m_pfnDatabase[i].pfn = i;
            m_pfnDatabase[i].state = PfnState::Free;
            m_pfnDatabase[i].referenceCount = 0;
            m_freeList.push_back(i);
        }

        m_currentTick = 1000;
        m_telemetry = {};
        m_telemetry.totalPhysicalPages = totalMemoryPages;
        m_telemetry.freePages = totalMemoryPages;

        // Perform initial background zeroing pass
        zeroFreePages(totalMemoryPages / 2);
    }

    /**
     * @brief Converts Free pages to Zeroed pages.
     */
    size_t zeroFreePages(size_t count) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        size_t zeroedCount = 0;
        while (!m_freeList.empty() && zeroedCount < count) {
            uint64_t pfn = m_freeList.front();
            m_freeList.pop_front();

            m_pfnDatabase[pfn].state = PfnState::Zeroed;
            m_zeroedList.push_back(pfn);
            zeroedCount++;
        }
        updateTelemetry();
        return zeroedCount;
    }

    /**
     * @brief Allocates virtual memory in a process address space.
     */
    NtStatus allocateVirtualMemory(
        ProcessAddressSpace& vas,
        uintptr_t& baseAddress,
        size_t size,
        uint32_t allocationType,
        uint32_t protect
    ) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        NtStatus st = vas.allocate(baseAddress, size, allocationType, protect);
        if (NT_SUCCESS(st)) {
            size_t aligned = (size + PageMask4KB) & ~PageMask4KB;
            m_telemetry.currentCommitBytes += aligned;
            if (m_telemetry.currentCommitBytes > m_telemetry.peakCommitBytes) {
                m_telemetry.peakCommitBytes = m_telemetry.currentCommitBytes;
            }
        }
        return st;
    }

    /**
     * @brief Resolves a Page Fault via Demand-Zero or Transition paging.
     */
    NtStatus handlePageFault(
        ProcessAddressSpace& vas,
        ProcessWorkingSet& ws,
        uintptr_t faultingAddress,
        uint32_t faultFlags
    ) {
        (void)faultFlags;
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        m_telemetry.pageFaultCount++;
        m_currentTick++;

        // Verify address is inside a valid committed VAD
        const auto* vad = vas.findVad(faultingAddress);
        if (!vad) {
            return NtStatus::AccessViolation;
        }

        uintptr_t pageAlignedAddr = faultingAddress & ~PageMask4KB;

        // Check if page is on the Standby or Modified list (Transition Fault)
        for (auto it = m_standbyList.begin(); it != m_standbyList.end(); ++it) {
            uint64_t pfn = *it;
            if (m_pfnDatabase[pfn].virtualAddress == pageAlignedAddr) {
                m_standbyList.erase(it);
                m_pfnDatabase[pfn].state = PfnState::Active;
                m_pfnDatabase[pfn].referenceCount = 1;
                m_pfnDatabase[pfn].lastAccessTick = m_currentTick;

                ws.insertPage(pageAlignedAddr, pfn, vad->protection, m_currentTick);
                m_telemetry.transitionFaults++;
                updateTelemetry();
                return NtStatus::Success;
            }
        }

        // Demand-Zero Fault: acquire page from Zeroed list (or Free list)
        uint64_t allocatedPfn = 0;
        if (!m_zeroedList.empty()) {
            allocatedPfn = m_zeroedList.front();
            m_zeroedList.pop_front();
            m_telemetry.demandZeroFaults++;
        } else if (!m_freeList.empty()) {
            allocatedPfn = m_freeList.front();
            m_freeList.pop_front();
            m_telemetry.demandZeroFaults++;
        } else {
            // Memory exhaustion: trigger emergency working set trim
            return NtStatus::InsufficientResources;
        }

        auto& pfnEntry = m_pfnDatabase[allocatedPfn];
        pfnEntry.state = PfnState::Active;
        pfnEntry.referenceCount = 1;
        pfnEntry.virtualAddress = pageAlignedAddr;
        pfnEntry.lastAccessTick = m_currentTick;

        ws.insertPage(pageAlignedAddr, allocatedPfn, vad->protection, m_currentTick);
        updateTelemetry();
        return NtStatus::Success;
    }

    /**
     * @brief Trims working set by evicting pages to Standby or Modified lists.
     */
    size_t trimWorkingSet(ProcessWorkingSet& ws, size_t pagesToEvict) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        auto evicted = ws.selectPagesToTrim(pagesToEvict);
        m_telemetry.workingSetTrims++;
        m_telemetry.pagesEvicted += evicted.size();

        for (const auto& entry : evicted) {
            uint64_t pfn = entry.pfn;
            if (pfn < m_pfnDatabase.size()) {
                auto& pfnEntry = m_pfnDatabase[pfn];
                pfnEntry.referenceCount = 0;

                if (pfnEntry.modified) {
                    pfnEntry.state = PfnState::Modified;
                    m_modifiedList.push_back(pfn);
                } else {
                    pfnEntry.state = PfnState::Standby;
                    m_standbyList.push_back(pfn);
                }
            }
        }

        updateTelemetry();
        return evicted.size();
    }

    /**
     * @brief Flushes all modified pages to standby list (simulating paging out to disk).
     */
    size_t flushModifiedPages() {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        size_t count = m_modifiedList.size();
        while (!m_modifiedList.empty()) {
            uint64_t pfn = m_modifiedList.front();
            m_modifiedList.pop_front();

            auto& pfnEntry = m_pfnDatabase[pfn];
            pfnEntry.modified = false;
            pfnEntry.state = PfnState::Standby;
            m_standbyList.push_back(pfn);
        }
        updateTelemetry();
        return count;
    }

    [[nodiscard]] DaytonaTelemetry getTelemetry() const noexcept {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_telemetry;
    }

private:
    DaytonaMemoryExecutive() {
        initialize(8192);
    }

    void updateTelemetry() {
        m_telemetry.freePages = m_freeList.size();
        m_telemetry.zeroedPages = m_zeroedList.size();
        m_telemetry.standbyPages = m_standbyList.size();
        m_telemetry.modifiedPages = m_modifiedList.size();
        m_telemetry.activePages = m_telemetry.totalPhysicalPages - 
            (m_telemetry.freePages + m_telemetry.zeroedPages + m_telemetry.standbyPages + m_telemetry.modifiedPages);
    }

    mutable std::recursive_mutex m_mutex;
    uint64_t m_currentTick{1000};
    DaytonaTelemetry m_telemetry{};

    std::vector<PfnEntry> m_pfnDatabase;
    std::deque<uint64_t> m_freeList;
    std::deque<uint64_t> m_zeroedList;
    std::deque<uint64_t> m_standbyList;
    std::deque<uint64_t> m_modifiedList;
};

} // namespace micant::daytonamm
